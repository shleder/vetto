![vetto — a kernel wall between the AI agent and your machine](../assets/readme/hero.svg)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.3.13"><img src="https://img.shields.io/badge/version-0.3.13-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/crates/v/vetto?logo=rust&style=flat-square&cacheSeconds=60" alt="crates.io"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="License"></a>
</p>

面向 AI 编程智能体（**Claude Code**、**OpenAI Codex CLI**、**Cursor**、**Gemini**、**Aider**）的无守护进程、无 root 权限的内核级沙箱与策略执行运行时。Vetto 在 `fork()` 和 `execve()` 之间直接注入不可变的内核级安全边界，初始化延迟低于 4 毫秒。

---

## 事实胜于承诺

自主智能体执行非确定性代码。不可信的依赖钩子、提示词注入或幻觉命令可能会泄露主机凭据（`~/.ssh`、`~/.aws`、`.env`）或破坏文件系统。在 Vetto 下，未授权的系统调用会被确定性地拦截：

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

![Blocked exfiltration attempt under vetto](../assets/demo.svg)

### 故障关闭契约 (Exit 125)

如果隔离边界被破坏或所需的内核原语无法执行，执行将立即以退出码 125 终止。子进程树和孤儿进程将被同步清理。底层操作系统无法保证的安全功能将报告为不支持——安全性绝不会在暗中降级。

## 快速入门

### 1. 安装

通过包管理器：

```bash
# npm
npm install -g @shledery/vetto
# Homebrew
brew install shleder/tap/vetto
# Cargo
cargo install vetto
```

或通过独立安装脚本：

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. 透明的智能体沙箱

为您的编程智能体一键启用零配置沙箱。Vetto 在 `~/.vetto/shims` 中安装一个无破坏性的垫片（shim），并在 `PATH` 中拥有优先权：

```bash
vetto enable claude   # 支持 codex、gemini、cursor、aider 及其预设
claude                # 正常运行 — 在内核边界完全受沙箱保护
```

### 3. 直接执行与 MCP 隔离

在严格的默认隔离下运行独立脚本：

```bash
vetto run -- python script.py
vetto -- npm test
```

隔离 Model Context Protocol (MCP) 服务器二进制文件，限制其访问路径并禁用网络出口：

```bash
vetto mcp wrap --allow ./data --net off -- <mcp-server-binary>
```

审查安全事件并验证平台执行情况：

```bash
vetto audit --latest --recap    # 审查被拦截的系统调用和文件操作
vetto doctor --fix              # 探测内核 LSM 支持情况并修复 shell 钩子
```

## 平台保证

Vetto 基于非特权用户空间可用的内核功能，执行不可变的三层边界模型：

| 平台 / 层级 | 文件系统隔离 | 网络隔离 | 进程生命周期 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Native)**<br>第 1 层 | Landlock LSM (ABI 1–6)<br>针对 `~/.ssh`、`~/.aws`、`.env` 的 Inode 级别 VFS 屏蔽 | 网络命名空间 (`CLONE_NEWNET`)<br>Loopback 隔离 + 本地 TCP/TLS 代理 | PID 命名空间 (`CLONE_NEWPID`)<br>确定性的进程树销毁 | 生产环境 |
| **Linux (WSL2)**<br>第 1 层 | 通过 WSL2 内核的 Landlock LSM<br>完整的 Inode 限制 | 虚拟机内的网络命名空间<br>隔离的代理出口 | PID 命名空间 + `/proc` 清理<br>完整的进程树销毁 | 生产环境 (推荐用于 Windows) |
| **macOS (Darwin)**<br>第 2 层 | Seatbelt (SBPL)<br>将写入限制在 `$PROJECT` 和 `/tmp` | 网络锁定<br>通过 `(deny network*)` 规则实现 `--net=off` | 进程组清理<br>kqueue 看门狗监督 | 标准环境 (需要针对 `~/Documents` 的全盘访问权限) |
| **Windows Native**<br>第 3 层 | AppContainer & LPAC<br>DACL 令牌限制 | 功能锁定<br>受限的网络 SID | 作业对象 (Job Objects)<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | 护栏环境 (对于第 1 层请使用 WSL2) |

## 二进制完整性与证明

版本发布通过自动化的 GitHub Actions 工作流构建，并具有公开的加密验证：

- **SLSA 第 3 级来源证明**: 为所有发布的二进制文件生成 In-toto 构建证明。
- **Minisign 签名**: 与每个版本存档一起发布，公钥为 `75ECEC9B5080C590`。
- **加密校验和**: 在安装期间生成并验证独立的 SHA256 哈希值。

## 文档

- [Platform Backends & Boundary Specs](platform-backends.md)
- [Agent Presets & Registry](agents.md)
- [Threat Model & Security Assumptions](threat-model.md)
- [Exit Codes & Failure Modes](exit-codes.md)
- [Vulnerability Reporting (SECURITY.md)](../SECURITY.md)

## 贡献

欢迎贡献。请从 main 分支创建分支。所有安全边界的断言都必须包含相应的内核验证测试用例。拉取请求 (PR) 会在 GitHub Actions CI 中的 Linux 和 macOS 运行器上进行验证。

## 许可证

基于 Apache License, Version 2.0 授权 ([LICENSE](../LICENSE))。
