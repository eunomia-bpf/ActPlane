source AGENT = exec "claude"
source AUDIT_CHANGE = file "**/src/functions/**"
rule update-types-for-audit-ops:
  notify exec "git" "commit" if AGENT and AUDIT_CHANGE
  because "When adding new audit operations, you must also update src/types.ts"
