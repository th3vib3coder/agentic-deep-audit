"""Scientific and data provenance extraction."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS


TEXT_EXTENSIONS = {".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".py", ".r", ".nf", ".smk", ".cwl", ".ipynb", ".tsv", ".csv"}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return read_json_capped(path, label="scientific input")


def evidence_by_path(audit_dir: Path) -> dict[str, str]:
    evidence = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("path")): str(item.get("id")) for item in evidence.get("evidence", []) if isinstance(item, dict) and item.get("path") and item.get("id")}


def simple_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for match in re.finditer(r"(?im)^\s*([A-Za-z][\w.-]*)\s*[:=]\s*[\"']?([^\"'\n#\]]+)", text):
        values[match.group(1).lower()] = match.group(2).strip().strip(",")
    return values


def read_text(repo_path: Path, path_value: str) -> str:
    try:
        return read_text_auto_capped(repo_path / path_value, encoding="utf-8", errors="replace", label="scientific source")
    except (OSError, FileSizeLimitError):
        return ""


def source_method(path_value: str, text: str) -> tuple[str, str, bool]:
    suffix = Path(path_value).suffix.lower()
    name = Path(path_value).name.lower()
    if suffix in {".yaml", ".yml", ".json", ".toml"} and name != "package.json":
        return "config_file_value", "high", False
    if name in {"requirements.txt", "pyproject.toml", "package.json", "cargo.toml"}:
        return "manifest_or_lockfile", "high", False
    if suffix == ".ipynb":
        return "notebook_metadata", "medium", False
    if suffix in {".md", ".txt"}:
        return "comment_or_docstring", "medium", True
    if name == "dockerfile":
        return "dockerfile_image_tag", "high", False
    return "heuristic_inference", "low", True


class ScientificRecorder:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self._seen: set[tuple[str, str, str]] = set()

    def add(self, category: str, observed_value: dict[str, Any], evidence_id: str, detection_method: str, confidence: str, requires_human_decision: bool, path_value: str) -> None:
        key = (category, json.dumps(observed_value, sort_keys=True), evidence_id)
        if key in self._seen:
            return
        self._seen.add(key)
        self.records.append(
            {
                "record_id": f"sci-{len(self.records) + 1:06d}",
                "category": category,
                "observed_value": {**observed_value, "source_path": path_value},
                "evidence_ids": [evidence_id],
                "confidence": confidence,
                "detection_method": detection_method,
                "requires_human_decision": requires_human_decision,
            }
        )


def detect_dataset(text: str, path_value: str, evidence_id: str, recorder: ScientificRecorder, method: str, confidence: str, requires_human: bool) -> None:
    values = simple_key_values(text)
    observed: dict[str, Any] = {}
    for key in ["dataset_path", "data_path", "input_data", "dataset"]:
        if key in values:
            observed["path"] = values[key]
            break
    for key in ["dataset_sha256", "sha256", "data_sha256"]:
        if key in values and re.fullmatch(r"[A-Fa-f0-9]{32,64}", values[key]):
            observed["sha256"] = values[key]
            break
    for key in ["source_url", "dataset_url", "data_url"]:
        if key in values and values[key].startswith(("http://", "https://")):
            observed["source_url"] = values[key]
            break
    if observed:
        recorder.add("dataset_provenance", observed, evidence_id, method, confidence, requires_human, path_value)


def detect_pipeline_and_tools(text: str, path_value: str, evidence_id: str, recorder: ScientificRecorder, method: str, confidence: str, requires_human: bool) -> None:
    name = Path(path_value).name.lower()
    suffix = Path(path_value).suffix.lower()
    values = simple_key_values(text)
    if suffix == ".nf" or name == "main.nf":
        recorder.add("pipeline_version", {"workflow_engine": "nextflow"}, evidence_id, "manifest_or_lockfile", "high", False, path_value)
    if suffix == ".smk" or name == "snakefile":
        recorder.add("pipeline_version", {"workflow_engine": "snakemake"}, evidence_id, "manifest_or_lockfile", "high", False, path_value)
    if suffix == ".cwl":
        recorder.add("pipeline_version", {"workflow_engine": "cwl"}, evidence_id, "manifest_or_lockfile", "high", False, path_value)
    if name == "makefile":
        recorder.add("reproducibility_makefile", {"makefile": path_value}, evidence_id, "manifest_or_lockfile", "high", False, path_value)
    if name == "dockerfile":
        match = re.search(r"(?im)^\s*FROM\s+([^\s]+)", text)
        if match:
            image = match.group(1)
            observed = {"container_image": image}
            digest = re.search(r"sha256:[A-Fa-f0-9]{32,64}", image)
            if digest:
                observed["digest"] = digest.group(0)
            recorder.add("tool_version", observed, evidence_id, "dockerfile_image_tag", "high", False, path_value)
    for key, value in values.items():
        if key.endswith("_version"):
            recorder.add("tool_version", {"tool": key.removesuffix("_version"), "version": value}, evidence_id, method, confidence, requires_human, path_value)
    for match in re.finditer(r"(?im)^\s*([A-Za-z][\w.-]+)==([^\s#]+)", text):
        recorder.add("tool_version", {"tool": match.group(1), "version": match.group(2)}, evidence_id, "manifest_or_lockfile", "high", False, path_value)


def detect_parameters_and_domain(text: str, path_value: str, evidence_id: str, recorder: ScientificRecorder, method: str, confidence: str, requires_human: bool) -> None:
    values = simple_key_values(text)
    parameter_keys = ["seed", "random_seed", "n_neighbors", "resolution", "learning_rate", "batch_size"]
    parameters = {key: values[key] for key in parameter_keys if key in values}
    if parameters:
        recorder.add("parameters_and_seeds", parameters, evidence_id, method, confidence, requires_human, path_value)
    if "genome_build" in values or re.search(r"\b(GRCh\d+|hg\d+)\b", text):
        build = values.get("genome_build") or re.search(r"\b(GRCh\d+|hg\d+)\b", text).group(1)
        recorder.add("genome_build", {"build": build}, evidence_id, method, confidence, requires_human, path_value)
    organism = values.get("organism")
    taxon = values.get("taxon_id") or values.get("taxon")
    if organism or taxon:
        recorder.add("organism_taxon", {"organism": organism, "taxon": taxon}, evidence_id, method, confidence, requires_human, path_value)
    annotation = values.get("annotation_version") or values.get("annotation_source")
    gencode = re.search(r"\bGENCODE\s*v?\d+\b", text, flags=re.IGNORECASE)
    if annotation or gencode or "RefSeq" in text:
        annotation_value = annotation or (gencode.group(0) if gencode else "RefSeq")
        recorder.add("annotation_version", {"annotation": annotation_value}, evidence_id, method, confidence, requires_human, path_value)
    if re.search(r"\b(ENSG\d{5,}|sample[_-]?id|cell[_-]?id|gene[_-]?id)\b", text, flags=re.IGNORECASE):
        recorder.add("sample_cell_gene_ids", {"identifier_signal": "sample/cell/gene identifiers observed"}, evidence_id, method, confidence, requires_human, path_value)


def detect_normalization_confounders_and_models(text: str, path_value: str, evidence_id: str, recorder: ScientificRecorder, method: str, confidence: str, requires_human: bool) -> None:
    values = simple_key_values(text)
    normalization = values.get("normalization_method") or values.get("normalization")
    if normalization or re.search(r"\b(TPM|CPM|log1p|log scale|batch correction)\b", text, flags=re.IGNORECASE):
        recorder.add("normalization_assumptions", {"normalization": normalization or "textual normalization signal"}, evidence_id, method, confidence, requires_human, path_value)
    confounder = values.get("confounders") or values.get("confounder") or values.get("covariates")
    if confounder or re.search(r"\b(confounder|covariate|donor effect|sample effect)\b", text, flags=re.IGNORECASE):
        recorder.add("analysis_confounder", {"confounder": confounder or "textual confounder signal"}, evidence_id, method, confidence, requires_human, path_value)
    batch_key = values.get("batch_key") or values.get("batch")
    if batch_key or re.search(r"\b(batch_key|batch model|batch correction)\b", text, flags=re.IGNORECASE):
        recorder.add("batch_confounder_model", {"batch_model": batch_key or "textual batch signal"}, evidence_id, method, confidence, requires_human, path_value)
    checkpoint = values.get("model_checkpoint") or values.get("checkpoint")
    if checkpoint or re.search(r"\b[\w./-]+\.(pt|pkl|h5|bin)\b", text, flags=re.IGNORECASE):
        recorder.add("model_checkpoint", {"checkpoint": checkpoint or "model artifact reference"}, evidence_id, method, confidence, requires_human, path_value)


def detect_notebook(text: str, path_value: str, evidence_id: str, recorder: ScientificRecorder) -> None:
    if Path(path_value).suffix.lower() != ".ipynb":
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    counts = [cell.get("execution_count") for cell in payload.get("cells", []) if isinstance(cell, dict) and cell.get("execution_count") is not None]
    if counts:
        recorder.add("notebook_execution_order", {"execution_counts": counts, "monotonic": counts == sorted(counts)}, evidence_id, "notebook_metadata", "medium", counts != sorted(counts), path_value)


def scientific_markdown(records: list[dict[str, Any]]) -> str:
    lines = ["# Scientific Provenance", ""]
    if not records:
        lines.extend(["no scientific signals detected", ""])
        return "\n".join(lines)
    lines.extend(["| Record | Category | Confidence | Requires Human Decision | Evidence | Observed |", "|---|---|---|---|---|---|"])
    for record in records:
        evidence = ", ".join(f"`{item}`" for item in record["evidence_ids"])
        observed = json.dumps(record["observed_value"], sort_keys=True)
        lines.append(f"| {record['record_id']} | {record['category']} | {record['confidence']} | {record['requires_human_decision']} | {evidence} | `{observed}` |")
    lines.append("")
    return "\n".join(lines)


def run_scientific_provenance(run_config: dict[str, Any], audit_dir: Path) -> None:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    evidence_lookup = evidence_by_path(audit_dir)
    repo_path = Path(str((file_index.get("repo") or run_config.get("repo") or {}).get("path") or ".")).resolve()
    recorder = ScientificRecorder()
    for record in file_index.get("records", []):
        if not isinstance(record, dict) or record.get("binary") is True:
            continue
        path_value = str(record.get("path_normalized") or record.get("path") or "")
        evidence_id = evidence_lookup.get(path_value)
        if not evidence_id:
            continue
        path = Path(path_value)
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name.lower() not in {"dockerfile", "makefile", "snakefile"}:
            continue
        text = read_text(repo_path, path_value)
        if not text:
            continue
        method, confidence, requires_human = source_method(path_value, text)
        detect_dataset(text, path_value, evidence_id, recorder, method, confidence, requires_human)
        detect_pipeline_and_tools(text, path_value, evidence_id, recorder, method, confidence, requires_human)
        detect_parameters_and_domain(text, path_value, evidence_id, recorder, method, confidence, requires_human)
        detect_normalization_confounders_and_models(text, path_value, evidence_id, recorder, method, confidence, requires_human)
        detect_notebook(text, path_value, evidence_id, recorder)
    write_json(audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE"], {"schema_version": "1.0", "run_id": run_config.get("run_id"), "records": recorder.records})
    (audit_dir / ARTIFACT_PATHS["SCIENTIFIC_PROVENANCE_MD"]).write_text(scientific_markdown(recorder.records), encoding="utf-8")
