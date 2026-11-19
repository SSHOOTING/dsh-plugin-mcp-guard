import test from 'node:test'
import assert from 'node:assert/strict'
import {
  auditServers,
  formatReport,
  normalizeServers,
  redact,
} from '../lib/core.js'

const codes = (report) => report.servers.map((server) => server.findings.map((f) => f.code))

test('redact strips common credential shapes before output', () => {
  assert.equal(redact('api_key=secret123'), 'api_key=[redacted]')
  assert.equal(redact('https://x.dev/?token=abc&y=1'), 'https://x.dev/?token=[redacted]&y=1')
  assert.equal(redact('--token abc'), '--token [redacted]')
  assert.equal(redact('https://user:pass@example.com'), 'https://[redacted]@example.com')
  assert.equal(redact(new Error('boom password=s3cr3t')).includes('s3cr3t'), false)
})

test('empty config is clean and scores 100', () => {
  const report = auditServers({})
  assert.deepEqual(
    {
      total: report.total,
      audited: report.audited,
      skipped: report.skipped,
      flagged: report.flagged,
      findings: report.findings,
      score: report.score,
      verdict: report.verdict,
    },
    { total: 0, audited: 0, skipped: 0, flagged: 0, findings: 0, score: 100, verdict: 'clean' },
  )
  assert.deepEqual(report.servers, [])
})

test('flags a plain http:// URL but accepts https://', () => {
  const bad = auditServers({ web: { url: 'http://localhost:3000' } })
  assert.deepEqual(codes(bad), [['insecure-url']])
  assert.equal(bad.score, 75)
  assert.equal(bad.verdict, 'risk')
  assert.equal(bad.servers[0].endpoint, 'http://localhost:3000')

  const good = auditServers({ api: { url: 'https://api.example.com' } })
  assert.equal(good.findings, 0)
  assert.equal(good.score, 100)
  assert.equal(good.verdict, 'clean')
  assert.equal(good.servers[0].endpoint, 'https://api.example.com')
})

test('flags a server with no url and no command', () => {
  const report = auditServers({ empty: {} })
  assert.deepEqual(codes(report), [['missing-endpoint']])
  assert.equal(report.findings, 1)
  assert.equal(report.score, 90)
  assert.equal(report.verdict, 'review')
  assert.equal(report.servers[0].endpoint, null)

  const blank = auditServers({ blank: { url: '', command: '   ' } })
  assert.equal(blank.findings, 1)
})

test('flags wildcard, boolean, and broad autoApprove values', () => {
  const report = auditServers({
    a: { url: 'https://a.dev', autoApprove: ['*'] },
    b: { url: 'https://b.dev', autoApprove: ['all'] },
    c: { url: 'https://c.dev', autoApprove: true },
  })
  assert.deepEqual(codes(report), [
    ['wildcard-auto-approve'],
    ['broad-auto-approve'],
    ['wildcard-auto-approve'],
  ])
  assert.equal(report.findings, 3)
  assert.equal(report.flagged, 3)
  assert.equal(report.score, 35)
  assert.equal(report.verdict, 'risk')
})

test('flags permissions containing * or all, case-insensitively', () => {
  const report = auditServers({
    p1: { url: 'https://p1.dev', permissions: ['*'] },
    p2: { url: 'https://p2.dev', permissions: 'all' },
    p3: { url: 'https://p3.dev', permissions: ['read', 'write'] },
  })
  assert.deepEqual(codes(report), [['wildcard-permission'], ['wildcard-permission'], []])
  assert.equal(report.findings, 2)
  assert.equal(report.flagged, 2)
  assert.equal(report.score, 50)
  assert.equal(report.verdict, 'risk')
})

test('detects shell -c invocation across Windows and POSIX forms', () => {
  const report = auditServers({
    win: { command: 'C:\\Windows\\System32\\cmd.exe', args: ['/c', 'whoami'] },
    lin: { command: '/bin/bash', args: ['-c', 'echo hi'] },
    sh: { command: 'sh', args: ['-c', 'id'] },
    safe: { command: 'node', args: ['-c', 'harmless'] },
    noflag: { command: 'bash', args: ['script.sh'] },
  })
  assert.deepEqual(codes(report), [
    ['shell-invocation'],
    ['shell-invocation'],
    ['shell-invocation'],
    [],
    [],
  ])
  assert.equal(report.total, 5)
  assert.equal(report.audited, 5)
  assert.equal(report.findings, 3)
  assert.equal(report.score, 25)
  assert.equal(report.verdict, 'risk')
  assert.equal(report.servers[3].endpoint, 'stdio: node')
})

test('disabled servers are skipped, including truthy string form', () => {
  const report = auditServers({
    active: { url: 'http://x.dev' },
    off: { command: 'bash', args: ['-c', 'x'], disabled: true, url: 'http://bad.dev' },
    off2: { url: 'http://y.dev', disabled: 'true' },
  })
  assert.equal(report.total, 3)
  assert.equal(report.audited, 1)
  assert.equal(report.skipped, 2)
  assert.equal(report.flagged, 1)
  assert.equal(report.findings, 1)
  assert.equal(report.score, 75)
  assert.equal(report.verdict, 'risk')
  assert.equal(report.servers[1].disabled, true)
  assert.deepEqual(report.servers[1].findings, [])
  assert.equal(report.servers[2].disabled, true)
})

test('each finding code is emitted at most once per server', () => {
  const report = auditServers({
    a: {
      url: 'https://a.dev',
      permissions: ['*', 'all', 'write_*'],
      autoApprove: ['*', 'read_*'],
    },
  })
  assert.deepEqual(codes(report), [['wildcard-auto-approve', 'wildcard-permission']])
  assert.equal(report.findings, 2)
  assert.equal(report.score, 50)
  assert.equal(report.verdict, 'risk')
})

test('normalizeServers narrows untrusted input to known fields only', () => {
  const normalized = normalizeServers({
    svc: {
      url: 'https://x.dev',
      command: 'node',
      args: ['a'],
      permissions: ['read'],
      autoApprove: false,
      disabled: false,
      credential: 'do-not-serialize',
      extra: { secret: 'nope' },
    },
  })
  assert.equal(normalized.length, 1)
  assert.deepEqual(Object.keys(normalized[0]).sort(), [
    'args', 'autoApprove', 'command', 'disabled', 'name', 'permissions', 'url',
  ])
  assert.equal(normalized[0].url, 'https://x.dev')
  assert.equal(normalized[0].autoApprove, false)
  assert.deepEqual(normalizeServers(null), [])
  assert.deepEqual(normalizeServers([]), [])
})

test('malformed configs never throw and fall back safely', () => {
  for (const bad of [null, undefined, 'x', 42, [], true]) {
    const report = auditServers(bad)
    assert.equal(report.total, 0)
    assert.equal(report.score, 100)
    assert.equal(report.verdict, 'clean')
  }

  const report = auditServers({ a: null, b: 42, c: 'x', d: { url: {} } })
  assert.equal(report.total, 4)
  assert.equal(report.audited, 4)
  assert.equal(report.findings, 4)
  assert.equal(report.score, 60)
  assert.equal(report.verdict, 'review')
  assert.deepEqual(report.servers.map((s) => s.findings[0].code), [
    'missing-endpoint', 'missing-endpoint', 'missing-endpoint', 'missing-endpoint',
  ])
})

test('non-string list entries are ignored and unusual URLs are redacted', () => {
  const ignored = auditServers({ a: { url: 'https://a.dev', autoApprove: [1, {}, 'read'] } })
  assert.equal(ignored.findings, 0)

  const odd = auditServers({ odd: { url: 'custom-target' } })
  assert.equal(odd.findings, 0)
  assert.equal(odd.servers[0].endpoint, 'url (details redacted)')
})

test('uppercase flags are matched case-insensitively', () => {
  const report = auditServers({
    a: { url: 'HTTP://x.dev', permissions: ['ALL'], autoApprove: ['ALL'] },
  })
  assert.deepEqual(codes(report), [[
    'insecure-url', 'broad-auto-approve', 'wildcard-permission',
  ]])
  assert.equal(report.findings, 3)
  assert.equal(report.score, 35)
  assert.equal(report.verdict, 'risk')
})

test('formatReport produces redacted text and a known-field-only JSON report', () => {
  const report = auditServers({
    'token=abc123-server': {
      url: 'http://user:pass@localhost:3000/?api_key=zzz&q=1',
      autoApprove: ['*'],
    },
  })
  const text = formatReport(report)
  assert.doesNotMatch(text, /abc123/)
  assert.doesNotMatch(text, /pass/)
  assert.doesNotMatch(text, /zzz/)
  assert.match(text, /score 50\/100/)
  assert.match(text, /RISK/)
  assert.match(text, /\[http:\/\/localhost:3000\]/)

  const json = formatReport(report, { json: true })
  const parsed = JSON.parse(json)
  assert.deepEqual(Object.keys(parsed).sort(), [
    'audited', 'findings', 'flagged', 'score', 'servers', 'skipped', 'total', 'verdict',
  ])
  assert.deepEqual(Object.keys(parsed.servers[0]).sort(), [
    'disabled', 'endpoint', 'findings', 'name',
  ])
  assert.deepEqual(Object.keys(parsed.servers[0].findings[0]).sort(), [
    'code', 'message', 'severity',
  ])
  assert.doesNotMatch(json, /abc123|pass|zzz/)
})
