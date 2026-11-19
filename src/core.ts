/**
 * Pure, dependency-free core for dsh-plugin-mcp-guard.
 *
 * It inspects ONLY the in-memory `mcpServers` object supplied by the plugin
 * config. No network calls, no process spawning, no file access, no imports.
 * Only known fields are ever read or serialized, and every emitted string is
 * passed through redaction before it can be shown or JSON-encoded.
 */

export type Severity = 'low' | 'medium' | 'high'
export type Verdict = 'clean' | 'review' | 'risk'

export type FindingCode =
  | 'insecure-url'
  | 'missing-endpoint'
  | 'wildcard-auto-approve'
  | 'broad-auto-approve'
  | 'wildcard-permission'
  | 'shell-invocation'

export interface Finding {
  code: FindingCode
  severity: Severity
  message: string
}

export interface ServerAudit {
  /** Redacted server name from the config key. */
  name: string
  /** True when the config explicitly disables the server (never audited). */
  disabled: boolean
  /** Redacted, credential-free endpoint hint: scheme+host for URLs, basename for commands. */
  endpoint: string | null
  findings: Finding[]
}

export interface Report {
  servers: ServerAudit[]
  total: number
  audited: number
  skipped: number
  flagged: number
  findings: number
  /** 0–100; 100 means no audited server produced a finding. */
  score: number
  verdict: Verdict
}

/** Untrusted config is narrowed to exactly these fields and nothing else. */
export interface NormalizedServer {
  name: string
  disabled: boolean
  url: string | null
  command: string | null
  args: string[]
  permissions: string[]
  autoApprove: string[] | boolean | null
}

const SECRET =
  /((?:token|key|secret|password|authorization|bearer)[^\s:=]{0,24}[:=]\s*)[^\s&]+/gi
const QUERY_SECRET = /([?&](?:token|key|secret|password|auth)=)[^&#\s]+/gi
const FLAG_SECRET = /((?:--?)[a-z0-9-]*(?:token|key|secret|password|auth)[a-z0-9-]*[= ]+)[^\s]+/gi
const USERINFO = /(:\/\/)[^\s/@]+:[^\s/@]+@/g

/** Strip credential-looking substrings before anything is printed or serialized. */
export function redact(value: unknown): string {
  const text = value instanceof Error ? value.stack || value.message : String(value)
  return text
    .replace(USERINFO, '$1[redacted]@')
    .replace(SECRET, '$1[redacted]')
    .replace(QUERY_SECRET, '$1[redacted]')
    .replace(FLAG_SECRET, '$1[redacted]')
}

function clip(value: string, max = 60): string {
  return value.length > max ? `${value.slice(0, max)}…` : value
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() !== '' ? value : null
}

function asStringList(value: unknown): string[] {
  if (typeof value === 'string') return value.trim() === '' ? [] : [value]
  if (!Array.isArray(value)) return []
  const out: string[] = []
  for (const item of value) {
    if (typeof item === 'string') out.push(item)
  }
  return out
}

/** Defensively narrow an untrusted `mcpServers` object into known fields only. */
export function normalizeServers(value: unknown): NormalizedServer[] {
  if (!isRecord(value)) return []
  const out: NormalizedServer[] = []
  for (const [key, raw] of Object.entries(value)) {
    const record = isRecord(raw) ? raw : {}
    const disabled =
      record.disabled === true ||
      (typeof record.disabled === 'string' && record.disabled.toLowerCase() === 'true')

    let autoApprove: string[] | boolean | null = null
    if (typeof record.autoApprove === 'boolean') autoApprove = record.autoApprove
    else {
      const list = asStringList(record.autoApprove)
      if (list.length > 0) autoApprove = list
    }

    out.push({
      name: key,
      disabled,
      url: nonEmptyString(record.url),
      command: nonEmptyString(record.command),
      args: asStringList(record.args),
      permissions: asStringList(record.permissions),
      autoApprove,
    })
  }
  return out
}

/**
 * Build a safe endpoint hint. URLs are reduced to scheme+host with any
 * userinfo/path/query removed; commands are reduced to their basename.
 * Args are never emitted (they commonly carry credentials).
 */
function safeEndpoint(server: NormalizedServer): string | null {
  if (server.url) {
    const match = /^([a-z][a-z0-9+.-]*:\/\/)([^\s/?#]*)/i.exec(server.url.trim())
    if (!match) return 'url (details redacted)'
    let authority = match[2]
    const at = authority.lastIndexOf('@')
    if (at !== -1) authority = authority.slice(at + 1)
    return redact(`${match[1]}${authority}`)
  }
  if (server.command) {
    const normalized = server.command.replace(/\\/g, '/')
    const base = normalized.slice(normalized.lastIndexOf('/') + 1)
    return redact(`stdio: ${base || 'command'}`)
  }
  return null
}

const BROAD_AUTO_APPROVE = new Set([
  'all',
  'any',
  'everything',
  'every',
  'admin',
  'root',
  'execute',
  'exec',
  'shell',
])
const SHELLS = new Set(['cmd', 'sh', 'bash'])

function shellBasename(command: string): string {
  const normalized = command.trim().replace(/\\/g, '/')
  let base = normalized.slice(normalized.lastIndexOf('/') + 1).toLowerCase()
  if (base.endsWith('.exe')) base = base.slice(0, -4)
  return base
}

function invokesShell(server: NormalizedServer): boolean {
  if (!server.command || !SHELLS.has(shellBasename(server.command))) return false
  return server.args.some((arg) => arg.trim() === '-c' || arg.trim() === '/c')
}

function auditOne(server: NormalizedServer): Finding[] {
  const findings: Finding[] = []
  const add = (code: FindingCode, severity: Severity, message: string) => {
    if (findings.some((finding) => finding.code === code)) return
    findings.push({ code, severity, message: redact(message) })
  }

  if (server.url && /^http:\/\//i.test(server.url.trim())) {
    add('insecure-url', 'high', 'URL uses plain http:// instead of https://')
  }
  if (!server.url && !server.command) {
    add('missing-endpoint', 'low', 'No url or command: server has no transport endpoint')
  }

  if (typeof server.autoApprove === 'boolean') {
    if (server.autoApprove) {
      add('wildcard-auto-approve', 'high', 'autoApprove is true: every tool is auto-approved')
    }
  } else if (server.autoApprove) {
    for (const entry of server.autoApprove) {
      const normalized = entry.trim().toLowerCase()
      if (normalized.includes('*')) {
        add('wildcard-auto-approve', 'high', `autoApprove entry contains a wildcard: ${clip(entry)}`)
      } else if (BROAD_AUTO_APPROVE.has(normalized)) {
        add('broad-auto-approve', 'medium', `autoApprove entry is a broad tool name: ${clip(entry)}`)
      }
    }
  }

  for (const entry of server.permissions) {
    const normalized = entry.trim().toLowerCase()
    if (normalized === '*' || normalized === 'all' || normalized.includes('*')) {
      add('wildcard-permission', 'high', `permissions grants broad access: ${clip(entry)}`)
    }
  }

  if (invokesShell(server)) {
    add('shell-invocation', 'high', 'command invokes a shell with -c (arbitrary command execution)')
  }

  return findings
}

const WEIGHT: Record<Severity, number> = { low: 10, medium: 15, high: 25 }

/** Audit an untrusted `mcpServers` object into a deterministic, serializable report. */
export function auditServers(mcpServers: unknown): Report {
  const normalized = normalizeServers(mcpServers)
  const servers: ServerAudit[] = []
  let skipped = 0
  let flagged = 0
  let findingCount = 0
  let high = 0
  let any = 0
  let deduction = 0

  for (const item of normalized) {
    if (item.disabled) {
      skipped++
      servers.push({
        name: redact(item.name),
        disabled: true,
        endpoint: null,
        findings: [],
      })
      continue
    }

    const findings = auditOne(item)
    if (findings.length > 0) flagged++
    for (const finding of findings) {
      findingCount++
      deduction += WEIGHT[finding.severity]
      if (finding.severity === 'high') high++
      any++
    }
    servers.push({
      name: redact(item.name),
      disabled: false,
      endpoint: safeEndpoint(item),
      findings,
    })
  }

  const score = Math.max(0, 100 - deduction)
  const verdict: Verdict = high > 0 ? 'risk' : any > 0 ? 'review' : 'clean'

  return {
    servers,
    total: normalized.length,
    audited: normalized.length - skipped,
    skipped,
    flagged,
    findings: findingCount,
    score,
    verdict,
  }
}

/** Compact text report, or the full redacted report as pretty JSON. */
export function formatReport(report: Report, options: { json?: boolean } = {}): string {
  if (options.json) return JSON.stringify(report, null, 2)

  const head =
    `[mcp-guard] ${report.flagged}/${report.audited} audited server(s) flagged` +
    ` · ${report.findings} finding(s) · ${report.skipped} skipped · score ${report.score}/100` +
    ` · ${report.verdict.toUpperCase()}`

  if (report.total === 0) {
    return `${head}\n  no MCP servers configured (add mcpServers to the bundle config to audit them)`
  }

  const lines: string[] = [head]
  for (const server of report.servers) {
    if (server.disabled) {
      lines.push(`  ${server.name}  DISABLED (skipped)`)
      continue
    }
    const endpoint = server.endpoint ? `  [${server.endpoint}]` : ''
    if (server.findings.length === 0) {
      lines.push(`  ${server.name}${endpoint}  OK`)
      continue
    }
    lines.push(`  ${server.name}${endpoint}`)
    for (const finding of server.findings) {
      lines.push(
        `    ${finding.severity.toUpperCase().padEnd(6)} ${finding.code.padEnd(23)} ${finding.message}`,
      )
    }
  }

  const tip = report.verdict === 'clean'
    ? ''
    : '\nFix: review the flags above; prefer HTTPS, avoid wildcard permissions/autoApprove, and drop shell -c wrappers.'
  return lines.join('\n') + tip
}
