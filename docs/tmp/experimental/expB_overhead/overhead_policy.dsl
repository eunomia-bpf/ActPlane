label AGENT

source AGENT  = exec "**/codex"
source SECRET = file "**/.env"
source SECRET = file "**/id_rsa"
source PII    = file "/data/customers/**"

rule no-unapproved-commit:
  deny exec "**/git" @arg "commit" if AGENT unless after exec "**/pytest"
  effect audit
  reason "audit: commit gate"
rule no-unapproved-push:
  deny exec "**/git" @arg "push" if AGENT unless after exec "**/approve"
  effect audit
  reason "audit: push gate"
rule no-force-push:
  deny exec "**/git" @arg "--force" if AGENT unless after exec "**/confirm"
  effect audit
  reason "audit: force-push gate"
rule no-branch:
  deny exec "**/git" @arg "branch" if AGENT
  effect audit
  reason "audit: branch"
rule no-secret-egress:
  deny connect endpoint "*" if SECRET
  effect audit
  reason "audit: secret egress"
declassify SECRET by exec "**/redact"
rule no-secret-write-shared:
  deny write file "/shared/**" if SECRET
  effect audit
  reason "audit: secret to shared"
rule pii-internal-only:
  deny connect endpoint "*" if PII unless target "127."
  effect audit
  reason "audit: pii egress"
rule confine-writes:
  deny write file "/etc/**" if AGENT
  effect audit
  reason "audit: workspace"
rule readonly-research:
  deny exec "**/git" if AGENT unless after exec "**/unlock"
  effect audit
  reason "audit: readonly"
rule mediate-proddb:
  deny open file "**/prod.db" unless lineage-includes exec "**/migrate"
  effect audit
  reason "audit: mediation"
