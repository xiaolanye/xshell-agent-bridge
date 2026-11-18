# Agent 客户端接入

Xshell Agent Bridge 的 Agent 接口是标准 MCP stdio。每个客户端只负责启动 `src/mcp-stdio.mjs`；该进程会连接到共享守护进程，守护进程未启动时会自动拉起。

## 安全模式

在 MCP 服务的 `env` 中设置 `XSHELL_SAFETY_MODE`。省略时使用 `safe`，写入其他值会导致 MCP 启动报错。修改后重启对应的 MCP 客户端，调用 `xshell_health` 可以查看其生效模式。多个客户端共用守护进程时，各自独立配置。

| 模式 | 普通终端输入 | 识别出的危险命令 | Ctrl+C |
| --- | --- | --- | --- |
| `safe`（默认） | 弹窗确认 | 直接拒绝 | 弹窗确认 |
| `normal` | 直接发送 | 弹窗确认 | 弹窗确认 |
| `full` | 直接发送 | 直接发送 | 直接发送 |

`normal` 也会对标为高风险或严重风险的操作弹窗。危险命令识别沿用原有规则，覆盖已知命令形式。弹窗指 Xshell 本地确认，客户端自己的 MCP 工具审批另外配置。敏感凭据保护和 SCP 文件传输的确认流程适用于所有模式。

升级后需重启旧守护进程。原有 v0.4.0 Xshell 脚本可继续使用 `safe`。启用 `normal` 或 `full` 前，请在对应标签页重新运行新版脚本。

## Codex / ChatGPT desktop

项目已包含使用相对路径的 `.codex/config.toml`。重新打开此项目后，Codex、ChatGPT desktop 和 Codex IDE 扩展会加载这项配置。Codex 的 `default_tools_approval_mode = "writes"` 会独立审批写工具。可在现有的环境变量段中设置 Xshell 模式：

```toml
[mcp_servers.xshell.env]
XSHELL_AGENT_ID = "codex"
XSHELL_SAFETY_MODE = "safe"
```

也可以添加到用户级配置：

```powershell
codex mcp add xshell --env XSHELL_AGENT_ID=codex -- node "<PROJECT_ROOT>\src\mcp-stdio.mjs"
```

## Kimi Code CLI

项目已包含 `.kimi-code/mcp.json`。安装 Kimi Code CLI 后，在项目目录启动 `kimi`，再运行 `/mcp` 查看 `xshell`。Kimi 对未匹配永久权限规则的 MCP 调用默认询问；不要对全部 `mcp__xshell__*` 设置永久放行，因为其中包含终端写操作。

## Claude Code

项目已包含 `.mcp.json`。在项目目录启动 Claude Code，批准项目级 MCP server 后即可使用。也可手动添加：

```powershell
claude mcp add -s project xshell -e XSHELL_AGENT_ID=claude -- node "<PROJECT_ROOT>\src\mcp-stdio.mjs"
```

## 其他支持 MCP stdio 的 Agent

使用以下等价配置：

```json
{
  "command": "node",
  "args": [
    "<PROJECT_ROOT>\\src\\mcp-stdio.mjs"
  ],
  "cwd": "<PROJECT_ROOT>",
  "env": {
    "XSHELL_AGENT_ID": "your-agent-name",
    "XSHELL_SAFETY_MODE": "safe"
  }
}
```

同一 Xshell 标签页可以被多个 Agent 同时读取。写操作按标签页串行排队，并按发起方配置的安全模式决定是否弹窗。`<PROJECT_ROOT>` 表示你克隆本仓库后的实际绝对路径。

无论使用哪种 Agent 客户端，密码、口令、Passphrase、PIN、OTP、验证码、Token 和 API Key 都必须由用户直接在 Xshell 中输入。不要给相关写工具设置绕过桥接规则的替代通道。
