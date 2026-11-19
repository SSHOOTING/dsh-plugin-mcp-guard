# dsh-plugin-mcp-guard

**一条命令审查所有已配置的 MCP 服务并标出危险设置——绝不连接服务、绝不执行命令。**

MCP 配置会越攒越多：这里是明文 `http://` 端点，那里是 `permissions: ["*"]`，还有一句「临时测试用」的 `bash -c` 包装。`mcp-guard` 只检查 DSH profile 已经保存在内存里的配置对象，把这些设置变成一张带分数的精简报告。它严格只读：不开 socket、不启动进程、不写文件、不打印凭据值。

## 安装

```powershell
dsh plugin add dsh-plugin-mcp-guard
```

要求 Node `^22.19.0 || >=24`，DSH `>=0.2.0-rc.2 <0.3.0`。

## 30 秒演示

1. 在 profile 的 bundle 行里加入你的 MCP 服务（见「配置」）。
2. 任意 DSH 会话中输入 `/mcp-guard`。
3. 得到一张评分卡：

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

用 `/mcp-guard --json` 获取机器可读输出（CI、脚本、看板）。JSON 只含已知字段，脱敏规则与文本输出一致。

## 配置

bundle patch 默认放一个空 map。在 profile 的 `cordis.patch.yml` 里填充，或合并进已有的 MCP 配置：

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

| 字段 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `mcpServers` | object | `{}` | 服务名到配置的映射。 |
| `mcpServers.<name>.url` | string | — | HTTP(S) 端点。明文 `http://` 会被标记。 |
| `mcpServers.<name>.command` | string | — | stdio 可执行文件。与 `url` 都没有时标记「无端点」。 |
| `mcpServers.<name>.args` | string[] | `[]` | 参数。仅用于检测 shell `-c`，永不打印。 |
| `mcpServers.<name>.permissions` | string[] | `[]` | 任意 `*` / `all` 条目（忽略大小写）会被标记。 |
| `mcpServers.<name>.autoApprove` | boolean 或 string[] | `false` | `true`、含 `*` 的通配项，或宽泛名称（`all`、`admin`、`root`、`execute` 等）会被标记。 |
| `mcpServers.<name>.disabled` | boolean | `false` | 列为跳过，不参与审查。 |

未知字段会被忽略且不参与序列化。格式非法的取值会被收敛成空默认值，而不是抛错。

## 规则、计分与判定

| 代码 | 严重度 | 触发条件 |
|---|---|---|
| `insecure-url` | high | `url` 以 `http://` 开头（非 `https://`）。 |
| `missing-endpoint` | low | 既没有可用的 `url` 也没有 `command`。 |
| `wildcard-auto-approve` | high | `autoApprove: true` 或条目含 `*`。 |
| `broad-auto-approve` | medium | `autoApprove` 条目如 `all`、`admin`、`root`、`execute`。 |
| `wildcard-permission` | high | `permissions` 含 `*` 或 `all`。 |
| `shell-invocation` | high | `cmd`/`sh`/`bash`（含 `.exe` 与完整路径）且 args 中有 `-c` 或 `/c`。 |

每条发现扣分：high 25、medium 15、low 10，总分裁剪到 `0–100`。判定规则：存在 high → `risk`；存在任意发现 → `review`；否则 `clean`。同一代码对每个服务最多出现一次。被禁用的服务会跳过且不影响分数。

URL 会先缩成 `scheme://host`（去掉 userinfo、路径、查询串），命令缩成 basename，然后再做脱敏。参数与凭据值永不输出。

## 隐私与安全

- 只读取传给 `apply(ctx, config)` 的内存 `mcpServers` 对象。不引入任何主机文件系统或进程 API。
- 不连接任何 MCP 服务——不拨号、不探测、不握手。
- 不执行命令、不调用 shell、不创建子进程。`command`/`args` 只当普通字符串处理。
- 不写文件、不上报。
- 只序列化已知字段，且每个输出字符串都经过脱敏过滤（凭据、查询串密钥、命令行 flag 密钥、URL userinfo）。

## 兼容性

| 组件 | 支持范围 |
|---|---|
| DSH | `>=0.2.0-rc.2 <0.3.0` |
| Node | `^22.19.0 \|\| >=24.0.0` |
| Cordis | `>=4.0.0 <5` |
| 界面 | headless 与 web（只用命令注册表） |

## 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 找不到 `/mcp-guard` | bundle 行未安装 | 重跑 `dsh plugin add dsh-plugin-mcp-guard`，重启 DSH。 |
| 提示 `no MCP servers configured` | 行配置里 `mcpServers` 为空或缺失 | 在 profile `cordis.patch.yml` 里加这个 map；安装的 patch 只放 `{}`。 |
| 某服务显示 `DISABLED (skipped)` | 设置了 `disabled: true`（或字符串 `"true"`） | 想审查就删掉它。 |
| 标记结果过期 | profile 的 `cordis.patch.yml` 覆盖了 bundle 行 | 后写者胜；改 profile 里的那一行并重启。 |
| `--json` 看似为空 | 输出是同一份报告的美观打印 JSON | 交给 JSON 解析器；顶层键为 `servers`、`total`、`audited`、`skipped`、`flagged`、`findings`、`score`、`verdict`。 |

## 开发

```powershell
npm install
npm test
npm pack --dry-run
```

测试完全离线：合成配置夹具，不调用模型、不联网、不创建子进程。

## 许可证

[MIT](LICENSE)
