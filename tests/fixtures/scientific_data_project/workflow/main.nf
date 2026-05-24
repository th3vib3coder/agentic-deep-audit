nextflow.enable.dsl=2

workflow {
  take:
  reads
  main:
  Channel.fromPath('data/counts.tsv')
}
