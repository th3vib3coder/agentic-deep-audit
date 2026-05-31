# Container Adapter

Status: deferred. No Dockerfile ships in this package; a container image is added only after a
recorded operator GO confirming the approval criteria below. The adapter still declares the
nine required adapter-doc fields from `docs/contracts/adapter_contract.md`, so the deferred
contract is explicit rather than silent.

## adapter id

`container`

## user entry command

None yet — the container adapter is deferred. When approved, the entry would read-only-mount the
target repo against a published image, e.g.
`docker run --rm -v "$PWD:/repo:ro" agentic-deep-audit deep-audit run --config /repo/audit.config.yaml`.

## required files

None ship today. A future `Dockerfile` and `.dockerignore` at the package root would be
required, added only under the approval criteria below.

## optional files

A compose file for local multi-service audits (not planned for the first image).

## output directory

The container would write only to a mounted `audit/` volume; the target-repo mount stays
read-only.

## security model

- target-repo code execution: none (read-only repo mount);
- network: default-deny — the image runs with no egress unless the operator opts in per run;
- host config access: none — **no host secret mounts** are permitted;
- credentials: none baked into the image;
- redaction verification: the same provenance/redaction tests gate any image build;
- write permissions: confined to the mounted `audit/` volume.

## Security

The seven adapter security columns for `container` (deferred; the posture the approved image must honor):

| target execution | network default | host config access | credentials | redaction verification | no-exec enforcement | write permissions |
|---|---|---|---|---|---|---|
| none (read-only repo mount; never executes target-repo code) | denied (default-deny egress unless the operator opts in per run) | none (no host secret mounts are permitted) | none read (none baked into the image) | covered by the provenance/MCP redaction tests, which gate any image build | the PreToolUse hook blocks command execution; the engine performs no target-repo execution | confined to the generated `audit/` output tree (the mounted `audit/` volume); the target-repo mount stays read-only |

## expected skipped/deferred behavior

The container adapter is `deferred` and must not be marketed as supported. Container-specific
behavior is untested until an image exists and a smoke run is recorded.

## validation command

`python -m pytest tests/test_adapter_container_docs.py -q`

## ownership of docs/tests

`tests/test_adapter_container_docs.py`.

## Approval criteria (deferred → planned)

A container image is added only after the operator records GO confirming all of:

- **base-image policy**: a pinned, minimal, regularly-patched base image (digest-pinned), never
  `:latest`;
- **no host secret mounts**: the image and its run instructions never mount host credentials,
  SSH keys, cloud config, or agent host config;
- **network** default-deny: the audit runs with no network egress unless explicitly opted in per
  run, matching the engine's network policy;
- a recorded build + smoke run (build the image, run a fixture audit, validate the output)
  before any `container` status is promoted above `deferred`.
