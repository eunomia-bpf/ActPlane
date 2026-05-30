label AGENT

source AGENT  = exec "**/codex"
source SECRET = file "**/.env"
source SECRET = file "**/id_rsa"
source PII    = file "/data/customers/**"

rule no-unapproved-commit:
  notify exec "git" "commit" if AGENT unless after exec "**/pytest"
  reason "audit: commit gate"
rule no-unapproved-push:
  notify exec "git" "push" if AGENT unless after exec "**/approve"
  reason "audit: push gate"
rule no-force-push:
  notify exec "git" "--force" if AGENT unless after exec "**/confirm"
  reason "audit: force-push gate"
rule no-branch:
  notify exec "git" "branch" if AGENT
  reason "audit: branch"
rule no-secret-egress:
  notify connect endpoint "*" if SECRET
  reason "audit: secret egress"
declassify SECRET by exec "**/redact"
rule no-secret-write-shared:
  notify write file "/shared/**" if SECRET
  reason "audit: secret to shared"
rule pii-internal-only:
  notify connect endpoint "*" if PII unless target "127."
  reason "audit: pii egress"
rule confine-writes:
  notify write file "/etc/**" if AGENT
  reason "audit: workspace"
rule readonly-research:
  notify exec "git" if AGENT unless after exec "**/unlock"
  reason "audit: readonly"
rule mediate-proddb:
  notify open file "**/prod.db" unless lineage-includes exec "**/migrate"
  reason "audit: mediation"
