rule catch_all:
  notify exec "**"
  because "probe: wildcard-only exec target must match every comm"
