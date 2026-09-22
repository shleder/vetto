![vetto — a kernel wall between the AI agent and your machine](../assets/readme/hero.svg)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.3.13"><img src="https://img.shields.io/badge/version-0.3.13-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/npm/v/%40shledery%2Fvetto?logo=npm&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/crates/v/vetto?logo=rust&style=flat-square&cacheSeconds=60" alt="crates.io"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="License"></a>
</p>

AI コーディングエージェント (**Claude Code**、**OpenAI Codex CLI**、**Cursor**、**Gemini**、**Aider**) のための、デーモンレスかつルートレスなカーネルレベルのサンドボックスおよびポリシー強制ランタイムです。Vetto は、`fork()` と `execve()` の間に直接、変更不可能なセキュリティ境界を 4ms 未満の初期化レイテンシで注入します。

---

## 約束よりも証拠を

自律型エージェントは非決定的なコードを実行します。信頼できない依存関係のフック、プロンプトインジェクション、またはハルシネーション（幻覚）によるコマンドは、ホストの資格情報 (`~/.ssh`、`~/.aws`、`.env`) を漏洩させたり、ファイルシステムを破壊する可能性があります。Vetto の下では、不正なシステムコールは決定論的にブロックされます。

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

![Blocked exfiltration attempt under vetto](../assets/demo.svg)

### Fail-Closed 契約 (Exit 125)

分離境界が破られた場合、または必要なカーネルプリミティブを適用できない場合、実行は即座に終了コード 125 で停止します。子プロセスツリーおよび孤立したサブプロセスは同期的に消去されます。基盤となる OS が強制できない保証は「サポート対象外」として報告され、セキュリティが暗黙のうちに低下することはありません。

## クイックスタート

### 1. インストール

パッケージマネージャーを使用:

```bash
# npm
npm install -g @shledery/vetto
# Homebrew
brew install shleder/tap/vetto
# Cargo
cargo install vetto
```

または、スタンドアロンインストーラーをダウンロード:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. 透過的なエージェントサンドボックス

コーディングエージェント用のゼロコンフィギュレーションサンドボックスを一度有効にします。Vetto は `~/.vetto/shims` に非破壊的なシムをインストールし、`PATH` の優先順位を与えます:

```bash
vetto enable claude   # codex、gemini、cursor、aider、およびプリセットをサポート
claude                # 通常通り実行 — カーネル境界で完全にサンドボックス化
```

### 3. 直接実行と MCP 隔離

厳格なデフォルト隔離の下でスタンドアロンスクリプトを実行します:

```bash
vetto run -- python script.py
vetto -- npm test
```

Model Context Protocol (MCP) サーバーバイナリを隔離し、パスを制限してネットワーク送信を無効にします:

```bash
vetto mcp wrap --allow ./data --net off -- <mcp-server-binary>
```

セキュリティイベントを検査し、プラットフォームの強制状況を確認します:

```bash
vetto audit --latest --recap    # ブロックされたシステムコールとファイル操作を確認
vetto doctor --fix              # カーネル LSM のサポートを調査し、シェルフックを修復
```

## プラットフォームの保証

Vetto は、非特権ユーザースペースで利用可能なカーネル機能に基づき、不変の 3 層境界モデルを強制します:

| プラットフォーム / 階層 | ファイルシステム分離 | ネットワーク分離 | プロセスライフサイクル | ステータス |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Native)**<br>Tier 1 | Landlock LSM (ABI 1–6)<br>`~/.ssh`、`~/.aws`、`.env` 上の Inode レベル VFS マスキング | ネットワーク名前空間 (`CLONE_NEWNET`)<br>ループバック分離 + ローカル TCP/TLS ブローカー | PID 名前空間 (`CLONE_NEWPID`)<br>決定論的なプロセスツリーの解体 | プロダクション |
| **Linux (WSL2)**<br>Tier 1 | WSL2 カーネルを介した Landlock LSM<br>完全な Inode 制限 | 仮想マシン内のネットワーク名前空間<br>分離されたブローカーの出口 | PID 名前空間 + `/proc` クリーンアップ<br>完全なプロセスツリーの消去 | プロダクション (Windows 向けに推奨) |
| **macOS (Darwin)**<br>Tier 2 | Seatbelt (SBPL)<br>`$PROJECT` および `/tmp` への書き込み制限 | ネットワークロックダウン<br>`(deny network*)` ルールによる `--net=off` | プロセスグループのクリーンアップ<br>kqueue ウォッチドッグ監視 | スタンダード (`~/Documents` へのフルディスクアクセスが必要) |
| **Windows Native**<br>Tier 3 | AppContainer & LPAC<br>DACL トークン制限 | 機能ロックダウン<br>制限されたネットワーク SID | ジョブオブジェクト<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | ガードレール (Tier 1 カーネル名前空間には WSL2 を使用) |

## バイナリの整合性と証明

リリースは自動化された GitHub Actions ワークフローを介してビルドされ、公開暗号化検証が行われます:

- **SLSA Level 3 出所証明**: すべてのリリースバイナリに対して生成される In-toto ビルド証明。
- **Minisign 署名**: 公開鍵 `75ECEC9B5080C590` の下で各リリースアーカイブとともに公開されます。
- **暗号化チェックサム**: インストール中に生成および検証される独立した SHA256 ハッシュ。

## ドキュメント

- [Platform Backends & Boundary Specs](platform-backends.md)
- [Agent Presets & Registry](agents.md)
- [Threat Model & Security Assumptions](threat-model.md)
- [Exit Codes & Failure Modes](exit-codes.md)
- [Vulnerability Reporting (SECURITY.md)](../SECURITY.md)

## 貢献

貢献を歓迎します。main からブランチを作成してください。すべての境界アサーションには、対応するカーネル検証テストケースが含まれている必要があります。プルリクエストは、GitHub Actions CI の Linux および macOS ランナーに対して検証されます。

## ライセンス

Apache License, Version 2.0 に基づいてライセンスされています ([LICENSE](../LICENSE))。
