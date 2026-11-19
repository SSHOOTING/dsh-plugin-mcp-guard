import test from 'node:test'
import assert from 'node:assert/strict'
import { name, inject, apply } from '../lib/index.js'

function makeCtx() {
  const registered = []
  const logs = []
  const effects = []
  const labels = []
  let disposed = 0
  return {
    registered,
    logs,
    effects,
    labels,
    get disposed() { return disposed },
    commands: {
      register: (command) => {
        registered.push(command)
        return () => { disposed++ }
      },
    },
    effect: (body, label) => {
      effects.push([...body()])
      labels.push(label)
    },
    logger: { info: (m) => logs.push(m) },
  }
}

test('entry exports the bundle name and injects only commands', () => {
  assert.equal(name, 'dsh-plugin-mcp-guard')
  assert.deepEqual(inject, ['commands'])
})

test('apply registers /mcp-guard once and ties disposal to the Cordis lifecycle', () => {
  const ctx = makeCtx()
  apply(ctx)
  assert.equal(ctx.registered.length, 1)
  assert.equal(ctx.registered[0].name, 'mcp-guard')
  assert.equal(ctx.registered[0].input.hint, '[--json]')
  assert.equal(ctx.effects.length, 1)
  assert.equal(ctx.effects[0].length, 1)
  assert.match(ctx.labels[0], /mcp-guard/)
  ctx.effects[0][0]()
  assert.equal(ctx.disposed, 1)
  assert.match(ctx.logs[0], /loaded/)
})

test('handler audits the mcpServers passed as apply(ctx, config)', () => {
  const ctx = makeCtx()
  apply(ctx, { mcpServers: { web: { url: 'http://localhost:3000' } } })
  const command = ctx.registered[0]
  const result = command.handler({ rawInput: '' })
  assert.equal(result.kind, 'success')
  assert.match(result.text, /score 75\/100/)
  assert.match(result.text, /RISK/)
  assert.match(result.text, /insecure-url/)
  assert.match(result.text, /web/)
})

test('handler supports --json with the configured servers', () => {
  const ctx = makeCtx()
  apply(ctx, {
    mcpServers: {
      fs: { command: 'bash', args: ['-c', 'echo hi'], permissions: ['all'] },
    },
  })
  const result = ctx.registered[0].handler({ rawInput: '--json' })
  assert.equal(result.kind, 'success')
  const report = JSON.parse(result.text)
  assert.equal(report.total, 1)
  assert.equal(report.verdict, 'risk')
  assert.deepEqual(report.servers[0].findings.map((f) => f.code), [
    'wildcard-permission', 'shell-invocation',
  ])
})

test('handler survives missing config, missing rawInput, and hostile getters', () => {
  const ctx = makeCtx()
  apply(ctx)
  const result = ctx.registered[0].handler({})
  assert.equal(result.kind, 'success')
  assert.match(result.text, /no MCP servers configured/)

  const hostile = {}
  Object.defineProperty(hostile, 'mcpServers', {
    enumerable: true,
    get() { throw new Error('boom token=leak') },
  })
  const ctx2 = makeCtx()
  apply(ctx2, hostile)
  assert.equal(ctx2.registered.length, 1)
  const hostileResult = ctx2.registered[0].handler({ rawInput: '' })
  assert.equal(hostileResult.kind, 'success')
  assert.match(hostileResult.text, /no MCP servers configured/)
  assert.doesNotMatch(hostileResult.text, /leak/)
})
