source COMMAND = exec "**"
source SECRET = file "**/*.env"
source SECRET = file "**/*.env.local"
source SECRET = file "**/*.env.production"
source SECRET = file "**/*id_rsa"
source SECRET = file "**/*id_ed25519"
source SECRET = file "**/*credentials.json"
source SECRET = file "/root/.aws/credentials"
source SECRET = file "/root/.gemini/oauth_creds.json"
source SECRET = file "/etc/secrets/**"
source SECRET = file "/etc/ssl/private/**"
rule secret-no-network:
  block connect endpoint "*" if SECRET
  because "A process that opened a configured secret source may not create an IPv4 connection"
