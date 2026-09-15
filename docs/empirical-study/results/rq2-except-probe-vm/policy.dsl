source AGENT = exec "python3"
rule probe:
  notify write file "**/*.js" if AGENT unless target "**/dist/**"
  because "probe: repo-relative **/dist/** exception in tracepoint mode"
