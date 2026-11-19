import { auditServers, formatReport, redact } from './core.js'

export const name = 'dsh-plugin-mcp-guard'

/** The command registry is the only host service we activate. */
export const inject = ['commands']

interface CommandContext {
  commands: {
    register(command: {
      name: string
      description: string
      input?: { hint?: string }
      handler: (args: { rawInput?: string }) =>
        | { kind: 'success'; text: string }
        | { kind: 'error'; text: string }
    }): () => void
  }
  /** Cordis lifecycle scope; registers disposables so disable/reload leaves no duplicate command. */
  effect?: (body: () => Generator, label?: string) => void
  logger?: { info?: (message: string) => void; warn?: (message: string) => void }
}

/** DSH passes the bundle row's `config` as the second argument to apply(). */
function readMcpServers(config: unknown): unknown {
  try {
    if (config && typeof config === 'object' && 'mcpServers' in config) {
      return (config as Record<string, unknown>).mcpServers
    }
  } catch {
    // A hostile config object can throw from a getter; treat it as unconfigured.
  }
  return undefined
}

/**
 * Cordis bundle entry. Registers `/mcp-guard`, a read-only audit of the
 * configured MCP servers. It never connects to a server, spawns a process,
 * executes a command, or writes a file — it only inspects the config object.
 */
export function apply(ctx: CommandContext, config?: unknown): void {
  const mcpServers = readMcpServers(config)

  const dispose = ctx.commands.register({
    name: 'mcp-guard',
    description: 'Read-only audit of configured MCP servers for risky settings',
    input: { hint: '[--json]' },
    handler: ({ rawInput }) => {
      try {
        const report = auditServers(mcpServers)
        const json = (rawInput ?? '').trim() === '--json'
        return { kind: 'success', text: formatReport(report, { json }) }
      } catch (error) {
        return {
          kind: 'error',
          text: `[mcp-guard] failed: ${redact(error instanceof Error ? error.message : error)}`,
        }
      }
    },
  })

  if (typeof ctx.effect === 'function') {
    ctx.effect(function* () { yield dispose }, `${name} lifecycle`)
  }

  ctx.logger?.info?.('[dsh-plugin-mcp-guard] loaded (read-only; /mcp-guard available)')
}
