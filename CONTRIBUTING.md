# 贡献与发布指南

## 构建和测试

在 Windows x64 上使用 Rust 构建。现有便携包使用 `x86_64-pc-windows-gnu` 工具链。GNU 构建需要 PATH 中可用的 GCC 和 `dlltool`。使用 MSVC 工具链时，请安装 Visual Studio 的 C++ Build Tools，并在对应的开发者终端执行。

```powershell
cargo test --locked
.\build.ps1
```

`build.ps1 -Test` 可一次完成这两步。脚本将 EXE 和两个许可声明文件复制到 `dist/`。从这个目录运行的实例会占用 EXE。构建前请从托盘退出该实例，或在另一个源码副本中构建。

默认测试使用合成账号，覆盖协议编码、门户跳转、认证结果、网络探测、退避、托盘状态和本地配置。凭据管理器测试在普通 Windows 桌面登录会话中单独运行：

```powershell
cargo test --locked --test storage_roundtrip credential_vault_roundtrip -- --ignored
```

修改协议编码时，可用 Node.js 运行 `node tests/reference.mjs` 重新生成合成测试向量。请将向量更新与协议变更一起审查。

## 提交问题或修改

- 报告问题时附上版本、Windows 版本、接入方式（以太网或 Wi‑Fi）、是否启用 TUN、操作步骤和实际结果。网络问题可附上出错时段的脱敏日志。
- 提交改动时说明触发条件、行为变化和已完成的验证。新增测试优先覆盖原有测试无法发现的回归。
- `src/main.rs` 负责窗口和消息处理，`src/tray.rs` 负责托盘。后台流程、网卡与 HTTP 分别位于 `src/engine.rs`、`src/network.rs` 和 `src/http.rs`。协议和配置存储分别位于 `src/protocol.rs` 和 `src/storage.rs`。
- `--diagnose` 将网卡摘要写入数据目录的 `diagnostics.txt` 并退出。`--measure` 运行约 10 秒后将内存采样写入 `memory.json` 并退出。分享前请移除账号、IP 等个人信息。
- 开发时可用 `ZJU_ASSISTANT_DATA_DIR` 指向独立的测试目录，隔离配置、日志和凭据名。该模式跳过登录自启注册。

## 打包 Windows x64 便携版

1. 从要发布的提交构建，使 `Cargo.toml`、`Cargo.lock`、`CHANGELOG.md` 和版本标签一致。

```powershell
.\build.ps1 -Test -Package
```

2. 在 `dist/` 查看 Windows x64 ZIP 和对应的 `.zip.sha256`。ZIP 内含 EXE、README 和许可文件。依赖更新后，根据 Windows 构建核对 `dependency-licenses/`。
3. 解压 ZIP，在正常的 Windows 测试会话检查启动、托盘、退出、原地覆盖升级和登录自启。使用测试账号验证凭据保存，并在发布说明中记录实测的网络环境。
4. 检查 Git 暂存清单，确保本机配置、日志、诊断文件和构建产物留在本地。将 Windows ZIP 和 SHA-256 文件上传到对应标签的 GitHub Release，GitHub 会从标签生成源码压缩包。

GitHub Actions 在 Windows 上执行格式检查、Clippy、测试和 Release 构建。

[GitHub Releases 文档](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
