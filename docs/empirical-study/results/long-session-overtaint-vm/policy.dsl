source SECRET = file "/session.env"
rule long-session-no-egress:
  notify connect endpoint "*" if SECRET
  because "A process lineage that has read a secret remains in sensitive context"
