source AGENT = exec "python3"
rule probe_sink:
  notify write file "**/dist/**" if AGENT
  because "probe: repo-relative **/dist/** sink in tracepoint mode"
