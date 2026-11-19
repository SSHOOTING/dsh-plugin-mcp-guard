# dsh-plugin-mcp-guard

**One command audits every configured MCP server and flags risky settings — without ever connecting to a server or running a command.**

MCP configs accumulate quickly: a plain `http://` endpoint here, a `permissions: ["*"]` there, a `bash -c` wrapper "just for testing". `mcp-guard` inspects the config object your DSH profile already holds and turns those into a compact, scored report. It is strictly read-only: no sockets, no process spawning, no file writes, no credential values printed.

## Install

```powershell
dsh plugin add dsh-plugin-mcp-guard
```

Requires Node `^22.19.0 || >=24` and DSH `>=0.2.0-rc.2 <0.3.0`.

## 30-second demo

1. Add your MCP servers to the bundle row in your profile (see Configuration).
2. In any DSH session, type `/mcp-guard`.
3. You get a scorecard:

```text
[mcp-guard] 2/3 audited server(s) flagged · 4 finding(s) · 1 skipped · score 0/100 · RISK
  local-dev  [http://localhost:3000]
    HIGH   insecure-url            URL uses plain http:// instead of https://
    HIGH   wildcard-auto-approve   autoApprove entry contains a wildcard: *
  shell-tool  [stdio: bash]
    HIGH   shell-invocation        command invokes a shell with -c (arbitrary command execution)
  clean-one  [https://example.com]  OK
  legacy  DISABLED (skipped)
Fix: review the flags above; prefer HTTPS, avoid wildcard permissions/autoApprove, and drop shell -c wrappers.
```

Use `/mcp-guard --json` for machine-readable output (CI, scripts, dashboards). The JSON contains only known fields and is redacted the same way as text output.

## Configuration

The bundle patch seeds an empty map. Fill it in your profile's `cordis.patch.yml` (or merge it into an existing MCP config):

```yaml
- id: dsh-plugin-mcp-guard
  name: dsh-plugin-mcp-guard
  config:
    mcpServers:
      local-dev:
        url: http://localhost:3000
        autoApprove: ['*']
      shell-tool:
        command: bash
        args: ['-c', 'echo hi']
      clean-one:
        url: https://example.com
        permissions: [read]
      legacy:
        command: node
        args: [server.js]
        disabled: true
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mcpServers` | object | `{}` | Map of server name to its config object. |
| `mcpServers.<name>.url` | string | — | HTTP(S) endpoint. A plain `http://` URL is flagged. |
| `mcpServers.<name>.command` | string | — | stdio executable. Absent together with `url`, the server is flagged as having no endpoint. |
| `mcpServers.<name>.args` | string[] | `[]` | Arguments. Used only for shell `-c` detection; never printed. |
| `mcpServers.<name>.permissions` | string[] | `[]` | Any `*` / `all` entry (case-insensitive) is flagged. |
| `mcpServers.<name>.autoApprove` | boolean or string[] | `false` | `true`, a `*` wildcard, or a broad name (`all`, `admin`, `root`, `execute`, …) is flagged. |
| `mcpServers.<name>.disabled` | boolean | `false` | Server is listed as skipped and never audited. |

Unknown fields are ignored and never serialized. Malformed values are narrowed to empty defaults instead of throwing.

## Rules, score, and verdict

| Code | Severity | Trigger |
|---|---|---|
| `insecure-url` | high | `url` starts with `http://` (not `https://`). |
| `missing-endpoint` | low | Neither a usable `url` nor a `command`. |
| `wildcard-auto-approve` | high | `autoApprove: true` or an entry containing `*`. |
| `broad-auto-approve` | medium | `autoApprove` entry such as `all`, `admin`, `root`, `execute`. |
| `wildcard-permission` | high | `permissions` contains `*` or `all`. |
| `shell-invocation` | high | `cmd`/`sh`/`bash` (including `.exe` and full paths) with `-c` or `/c` in args. |

Each finding subtracts points: high 25, medium 15, low 10, clamped to `0–100`. The verdict is `risk` if any high-severity finding exists, `review` if any finding exists, otherwise `clean`. Each finding code appears at most once per server. Disabled servers are skipped and do not affect the score.

URLs are reduced to `scheme://host` with userinfo, path and query removed, and commands to their basename, before redaction. Args and credential values are never emitted.

## Privacy & safety

- Reads only the in-memory `mcpServers` object passed to `apply(ctx, config)`. No host filesystem or process APIs are imported.
- No network connections to any MCP server — nothing is dialed, pinged, or handshaked.
- No command execution, no shell, no child process. `command`/`args` are treated as inert strings.
- No file writes, no telemetry.
- Only known fields are serialized, and every emitted string passes through a redaction filter (credentials, query secrets, CLI flag secrets, URL userinfo).

## Compatibility

| Component | Supported |
|---|---|
| DSH | `>=0.2.0-rc.2 <0.3.0` |
| Node | `^22.19.0 \|\| >=24.0.0` |
| Cordis | `>=4.0.0 <5` |
| Surface | headless and web (command registry only) |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/mcp-guard` not found | Bundle row not installed | Re-run `dsh plugin add dsh-plugin-mcp-guard`, then restart DSH. |
| `no MCP servers configured` | `mcpServers` is empty or missing in the row config | Add the map to the profile `cordis.patch.yml`; the installed patch only seeds `{}`. |
| A server shows `DISABLED (skipped)` | `disabled: true` (or the string `"true"`) is set | Remove it if you want the server audited. |
| Flags look outdated | Profile `cordis.patch.yml` overrides the bundle row | The last write wins — edit the profile row, then restart. |
| `--json` looks empty | Output is pretty-printed JSON of the same report | Pipe to a JSON parser; the top-level keys are `servers`, `total`, `audited`, `skipped`, `flagged`, `findings`, `score`, `verdict`. |

## Development

```powershell
npm install
npm test
npm pack --dry-run
```

Tests are fully offline: synthetic config fixtures, no model, no network, no child processes.

## License

[MIT](LICENSE)

## Related plugins

- [dsh-plugin-safe-route](https://github.com/SSHOOTING/dsh-plugin-safe-route)
- [dsh-plugin-session-archive](https://github.com/SSHOOTING/dsh-plugin-session-archive)
- [dsh-plugin-token-budget](https://github.com/SSHOOTING/dsh-plugin-token-budget)
- [dsh-plugin-free-model-advisor](https://github.com/SSHOOTING/dsh-plugin-free-model-advisor)
