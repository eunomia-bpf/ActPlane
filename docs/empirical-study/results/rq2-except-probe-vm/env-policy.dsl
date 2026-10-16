source AGENT = exec "claude"
rule read-env-example:
  notify write file "**/.env" if AGENT
  because "Read .env.example before creating or modifying .env files"
