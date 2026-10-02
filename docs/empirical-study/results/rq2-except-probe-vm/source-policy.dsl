source CLI = file "**/src/lib/**"
rule probe_source:
  notify connect endpoint "*" if CLI
  because "probe: repo-relative **/src/lib/** file source in tracepoint mode"
