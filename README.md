# VPS Firewall

Debian 13 终端防火墙管理工具：以 UFW 为主，支持多端口管理、SSH 端口迁移和 Fail2ban 同步。

## 一键安装

仓库须公开，以下文件放在 `main` 分支根目录：`install.sh`、`vpsfw.sh`、`README.md`。

在 Debian 13 VPS 上以 root 执行；需要已安装 `curl` 和 CA 证书：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/macwk-com/vps-firewall/main/install.sh)
```

如果提示找不到 curl，先执行：

```bash
apt update && apt install -y curl ca-certificates
```

安装脚本下载主程序，检查 Bash 语法后保存为 `/usr/local/bin/vpsfw`，并打开菜单。安装快捷命令本身不会修改防火墙或 SSH 配置。

以后直接输入：

```bash
vpsfw
```

普通用户使用 `sudo vpsfw`。没有自己的域名也能使用上面的 GitHub 地址。私有仓库不能使用这条匿名下载命令。

也可以先下载、检查再执行：

```bash
curl -fSL https://raw.githubusercontent.com/macwk-com/vps-firewall/main/install.sh -o install.sh
less install.sh
bash install.sh
```

下面命令行示例中的 `bash vpsfw.sh`，安装后也可以直接写成 `vpsfw`。


适用于 Debian 13、直接运行在宿主机上的 Realm 和标准 `ssh.service`。主界面是终端彩色数字菜单，不需要安装图形桌面。

## 使用

把 `vpsfw.sh` 上传到 VPS，以 root 在文件所在目录运行：

```bash
bash vpsfw.sh
```

新服务器选择 **1. 初始化 UFW + Fail2ban**。已有这两个工具的服务器可以直接查看状态、管理端口或迁移 SSH，无需反复初始化。初始化会备份并覆盖 Fail2ban 的 `sshd.local`，并保留已有 UFW 规则。

菜单提供：

1. 初始化 UFW + Fail2ban
2. 查看状态和全部 UFW 规则
3. 添加一个或多个放行端口，选择 TCP、UDP 或两者
4. 删除本脚本管理的端口规则
5. 替换 Realm 放行端口（TCP 和 UDP）
6. 查看监听端口及程序
7. 启用或停用 UFW
8. 修改 SSH 端口，同步 SSH / UFW / Fail2ban
9. 确认迁移，关闭旧 SSH 入口
10. 回退尚未确认的 SSH 迁移
11. 查看 Fail2ban 状态，并按 SSH 配置同步端口
12. 查看备份位置

## SSH 端口迁移

例如从 2222 改为 38217：

1. 在服务商安全组放行 **38217/TCP**，保留当前 SSH 窗口。
2. 选择菜单 **8**，输入 `38217`。脚本先备份，再放行新端口，让 SSH 同时监听新旧端口，并让 Fail2ban 同时保护两者。
3. 新开终端，用 **38217** 登录服务器。继续使用原来的用户名、密码或密钥。
4. 在这个新连接里运行脚本，选择 **9**。脚本只保留新 SSH 监听，同步 Fail2ban，并删除带 `SSH` 注释的旧端口放行规则。

从旧连接无法执行第 4 步。如果新连接失败，旧端口仍保留，可以选择 **10** 回退。已经确认完成的迁移不支持菜单 10；要换回原端口，可再次使用菜单 8。

发生配置检查、重载或服务启动错误时，迁移过程会尝试恢复 SSH 和 Fail2ban 配置。新增的 UFW 放行规则保留，便于恢复访问。断电、强制终止等情况无法保证自动回退，请保留服务商网页控制台入口。

脚本针对标准 Debian SSH 服务。检测到 `ssh.socket`、自定义启动参数、非标准 `Include`、自定义 `ListenAddress` 或配置软链接时，会停止自动迁移并说明原因，不强行改写。脚本不会更改 SSH 的认证方式。

## 命令行仍然可用

```bash
# 初始化；这里填现有 SSH 端口，不会更改监听
bash vpsfw.sh --ssh-port 2222 --realm-ports 23456,41863

# TCP、UDP 分别添加，或使用 both
bash vpsfw.sh ports add 41863,59327 both
bash vpsfw.sh ports delete 41863 tcp
bash vpsfw.sh ports list

# Realm 端口管理命令
bash vpsfw.sh realm add 23456,41863
bash vpsfw.sh realm change 23456 53681
bash vpsfw.sh realm delete 41863

# 真正修改 SSH 端口：仍分开启新端口和确认两步
bash vpsfw.sh ssh change 38217
bash vpsfw.sh ssh finish
bash vpsfw.sh ssh rollback

# 查看状态 / 同步 Fail2ban
bash vpsfw.sh status
bash vpsfw.sh sync
```

业务端口管理只修改 UFW，不修改 Realm 的 `listen` / `remote` 或客户端配置。管理带 `Realm TCP/UDP` 或 `VPS TCP/UDP` 注释的规则；其他用途的规则不自动删除。其他宽泛放行规则仍可能允许同一端口。

## 备份及恢复入口

原配置存放在 `/var/backups/vps-security.*` 或 `/var/backups/vps-security-ssh.*`，具体路径在每次操作时显示。迁移中的状态存放在 `/var/lib/vps-security/ssh-pending`。备份权限仅限 root，可能包含敏感配置，请勿公开分享。

需要紧急恢复访问时，在保留的 SSH 会话或服务商控制台执行：

```bash
ufw disable
```

这不会解除 Fail2ban 封禁。若是自己的 IP 被 Fail2ban 封禁：

```bash
fail2ban-client set sshd unbanip 你的公网IP
```

## 验证范围

已完成 Bash 语法检查、隔离文件下的真实 OpenSSH 配置检查，以及端口管理、双端口迁移、会话确认、重载失败回退的模拟测试。尚未在真实 Debian 13 VPS 上验证 UFW、systemd、Fail2ban 的端到端行为。
