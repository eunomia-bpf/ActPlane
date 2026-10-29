# Frontier CLI and trusted inference transport

The pinned RepoGuardBench artifact includes an optional `ClaudeCLIBackend`. It keeps the official agent loop, action schema, defenses, sandbox and scorer, but uses a commercial CLI to produce the next structured action. The upstream paper separates this reference from its local-model headline aggregate. This lane will preserve that distinction.

## Live inspection and setup evidence

`scripts/inspect_cli.sh` inspected only the authorized ActPlane Workspace. The installed executable is `/usr/local/bin/claude`, version `2.1.296`. Authentication reported `loggedIn=true`, `oauth_token`, and `firstParty`. No login, credential migration, lifecycle change or account mutation was performed.

The benign model-only setup request succeeded. Requested CLI alias `opus` resolved to `claude-opus-5-5` in the actual result envelope's `modelUsage` keys, with `is_error=false`. This is a setup check, not a benchmark result. Remote evidence:

- `raw/cli-inspection/version.txt`, `help.txt`, and restricted `auth.json`.
- `raw/cli-inspection/smoke/cli-identity.json` and complete CLI result envelope.
- `raw/cli-inspection/channel-smoke/client.stdout`: an unprivileged, capability-free client received the expected benign response through the fixed-model transport.

## Exact reuse and necessary launcher deviation

`scripts/inference_transport.py::make_cli_backend()` subclasses the official backend without replacing its `chat()` implementation. Its default request deadline, message flattening, deny list and result handling remain from the pinned official artifact. Its cache is restricted to a root-owned private directory and is not shared across independent experiment cells.

The official deny list predates the installed CLI's expanded tools and MCP support. The lane therefore uses a root-owned launcher that additionally supplies the installed CLI's supported `--tools ""`, `--strict-mcp-config`, `--mcp-config '{"mcpServers":{}}'`, and `--no-session-persistence` options. This is an explicit launcher deviation that implements the upstream adapter's stated model-only intent. It is not a claim that the installed CLI's default configuration disables every tool. The launcher and cache are outside all worker-writable case trees. The launcher preserves the full official result envelope so the actual model identity is available despite the upstream backend dropping that field from its returned metadata.

The upstream CLI adapter does not apply the Ollama sampling/token-limit options passed to `chat()`. Its CLI reference therefore uses its own official configuration, and must not be described as a raw-model comparison with an identical inference budget.

## Transport boundary

`InferenceServer(model, raw_dir)` selects a fixed backend under the trusted host identity. It exposes a per-cell directory channel containing only JSON message requests and inference responses. The actual benchmark tool effects still execute in the unprivileged worker. `client_chat(channel, messages, options, stop)` works across the guest's shared filesystem, where a host Unix socket would not work across kernels.

The supervisor must pass a protected `raw_dir` outside any case directory recursively transferred to the worker. Backend requests, responses, launcher code and CLI credentials remain in root-owned private host directories. No credential is placed in a message or copied into the guest for CLI inference. The worker can request model inference, but cannot choose a backend executable, model, filesystem destination or shell command through the channel. Directory file descriptors, fixed filename patterns, exclusive writes and no-follow opens prevent channel symlinks from becoming privileged file operations.

The same message transport can serve Qwen and GLM so inference HTTP requests belong to the trusted control plane rather than the constrained tool process. This avoids treating a policy's denial of its own model connection as a malicious benchmark network effect. Every transmitted message and response remains in the remote raw evidence. The transport does not manufacture benchmark success, suppress model errors or change the official task predicates.
