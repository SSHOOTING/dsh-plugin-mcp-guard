# Changelog

## 0.1.0 (2026-11-19)

- Initial release.
- `/mcp-guard` command: read-only audit of configured MCP servers for plain `http://` URLs, missing endpoints, wildcard/broad `autoApprove`, wildcard `permissions`, and shell `-c` invocation.
- Disabled servers are listed as skipped and excluded from scoring.
- 0–100 safety score with `clean` / `review` / `risk` verdict.
- `/mcp-guard --json` emits a redacted, known-fields-only report.
- Config is read from DSH's `apply(ctx, config)` second argument; command registration is tied to `ctx.effect()` so disable/reload leaves no duplicate.
- Defensive normalization: unknown fields ignored, malformed values defaulted, all emitted strings redacted. No network, process spawning, or file writes.
- Fully offline test suite with synthetic config fixtures.
