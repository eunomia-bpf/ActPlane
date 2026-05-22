# MCP Test Fixture

This directory contains a minimal MCP server and test CLI for local smoke testing.
It is intentionally small, uses only the Python standard library, and supports two
transports:

- `stdio`: useful for local MCP process experiments
- `http`: useful for validating the current AgentSight-friendly network path

This is a test fixture, not the production AgentSight MCP implementation.

## Files

- `test_mcp_server.py`: minimal MCP server with `initialize`, `ping`, `tools/list`,
  and `tools/call`
- `test_mcp_cli.py`: test client that exercises the server end-to-end
- `fixture_note.txt`: local file read by the `read_fixture` test tool

## Tools exposed by the test server

- `echo`: returns the provided text
- `sum_numbers`: returns the numeric sum of a list
- `read_fixture`: reads `fixture_note.txt`

## Stdio mode

Run the CLI. It will spawn the server automatically:

```bash
python3 docs/mcp-test/test_mcp_cli.py --transport stdio
```

Expected output includes:

- `initialize`
- `tools/list`
- `tools/call echo`
- `tools/call sum_numbers`
- `tools/call read_fixture`

## HTTP mode

Start the server in one terminal:

```bash
python3 docs/mcp-test/test_mcp_server.py --transport http --host 127.0.0.1 --port 8765
```

Then run the CLI in another terminal:

```bash
python3 docs/mcp-test/test_mcp_cli.py --transport http --url http://127.0.0.1:8765/messages
```

The HTTP server also exposes a simple health endpoint:

```bash
curl http://127.0.0.1:8765/health
```

## AgentSight validation notes

- HTTP mode is the useful baseline for current MCP-over-network experiments.
- Stdio mode is the useful baseline for local MCP testing where the client and
  server communicate via pipes instead of HTTP/TLS.
- The fixture content is intentionally predictable so it is easier to recognize in
  captured logs, for example:
  - `echo:stdio-hello`
  - `echo:http-hello`
  - `sum:10.5`
  - `fixture:AgentSight MCP fixture payload for stdio and HTTP smoke tests.`
