# VPS Firewall

只管理服务器端口和 SSH：UFW 负责入站放行规则，Fail2ban 负责 SSH 登录失败封禁。适用于 Debian 13。

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

普通用户使用 `sudo vpsfw`，脚本会自动识别当前 SSH 连接的端口。没有自己的域名也能使用上面的 GitHub 地址。私有仓库不能使用这条匿名下载命令。

也可以先下载、检查再执行：

```bash
curl -fSL https://raw.githubusercontent.com/macwk-com/vps-firewall/main/install.sh -o install.sh
less install.sh
bash install.sh
```

下面命令行示例中的 `bash vpsfw.sh`，安装后也可以直接写成 `vpsfw`。


适用于 Debian 13 宿主机入站流量和标准 `ssh.service`，不管理应用或代理配置。主界面是终端彩色数字菜单，不需要安装图形桌面。

## 使用

把 `vpsfw.sh` 上传到 VPS，以 root 在文件所在目录运行：

```bash
bash vpsfw.sh
```

新服务器选择 **1. 初始化 UFW + Fail2ban**。已有这两个工具的服务器可以直接查看状态、管理端口或迁移 SSH，无需反复初始化。初始化只添加 SSH 放行，备份并覆盖 Fail2ban 的 `sshd.local`，保留已有 UFW 规则。通过 SSH 登录时自动使用当前连接的端口；在服务商网页控制台里运行才需要手动填写。其他端口需要时再添加。

菜单里每一步输入都会当场检查，输错会提示并重新输入；直接回车返回菜单。确认提示用 `y` / `n`，方括号里大写的是回车默认值。输入时方向键可以正常移动光标。

菜单提供：

1. 初始化 UFW + Fail2ban；已经初始化过会先说明，默认不重做
2. 查看防护状态、放行规则和正在封禁的 IP；脚本不管理的规则原样列出
3. 添加单端口、多个端口或范围；选择 TCP / UDP 和来源 IP / 网段；还没有程序监听时会提醒
4. 列出现有放行规则，按编号选择删除（可多选）
5. 列出现有放行规则，按编号选一条换成新端口（先添加新规则，再删除旧规则）
6. 查看监听端口、程序，以及防火墙是否放行（已放行 / 仅部分来源 / 未放行 / 仅本机访问）；另列出已放行但没有程序监听的端口
7. 显示防火墙当前状态，启用或停用 UFW
8. 修改 SSH 端口，同步 SSH / UFW / Fail2ban；迁移进行中时在这里确认或回退
9. 查看 Fail2ban 保护端口、封禁条件和封禁名单，可直接解封 IP；端口与 SSH 不一致或没在运行时提示同步
10. 查看最近几天的 SSH 登录记录：成功登录（时间、用户、来源 IP、密钥还是密码），失败尝试按来源 IP 汇总（次数、最近一次、试过的用户名、是否已被封禁），以及 Fail2ban 的封禁次数
11. SSH 登录方式：修改登录密码、管理公钥、关闭或打开密码登录，详见下文
12. 禁止或恢复别人 ping 这台服务器（IPv4 和 IPv6）；只改 UFW 里放行 ping 的那两行，其他 ICMP 和服务器自己 ping 别人都不受影响

## SSH 端口迁移

例如从 2222 改为 38217：

1. 在服务商安全组放行 **38217/TCP**，保留当前 SSH 窗口。
2. 选择菜单 **8**，输入 `38217`。脚本先备份，再放行新端口，让 SSH 同时监听新旧端口，并让 Fail2ban 同时保护两者。
3. 新开终端，用 **38217** 登录服务器。继续使用原来的用户名、密码或密钥。
4. 在这个新连接里运行脚本，选择菜单 **8**，再选「确认迁移」。脚本只保留新 SSH 监听，同步 Fail2ban，并删除带 `SSH` 注释的旧端口放行规则。

从旧连接无法执行第 4 步。如果新连接失败，旧端口仍保留，可以在菜单 **8** 里选「回退迁移」。回退会在 SSH 恢复旧端口后，删除迁移时为新端口添加的防火墙放行；迁移前就存在的规则不动。已经确认完成的迁移不能回退；要换回原端口，再做一次迁移即可。

发生配置检查、重载或服务启动错误时，迁移过程会尝试恢复 SSH 和 Fail2ban 配置。新增的 UFW 放行规则保留，便于恢复访问。断电、强制终止等情况无法保证自动回退，请保留服务商网页控制台入口。

脚本针对标准 Debian SSH 服务。检测到 `ssh.socket`、自定义启动参数、非标准 `Include`、自定义 `ListenAddress` 或配置软链接时，会停止自动迁移并说明原因，不强行改写。脚本不会更改 SSH 的认证方式。

## SSH 登录方式（菜单 11）

SSH 常用两种登录方式：密码，以及密钥。密钥分两半，**私钥**留在你自己电脑上、绝不外传，**公钥**放到服务器上用来核对。菜单 11 先显示密码登录是否允许、当前窗口是怎么登录的、这个用户有没有密码和几把公钥，然后提供三个功能：

- **修改密码**：默认改当前登录的用户，也可以选其他用户或 root。可以自己输入（至少 12 位、不能包含用户名，输入时不显示），或让脚本生成一个随机强密码，只显示一次。密码只通过标准输入交给系统，不会出现在命令参数、历史记录或日志里。Debian 13 默认 root 不能用密码登录 SSH，改 root 密码只影响服务商网页控制台和 `su`。
- **管理公钥**：列出服务器上已有的公钥；粘贴你电脑上 `.pub` 文件里的那一行即可添加，脚本会检查格式、去重并设好权限（误贴私钥会被拒绝）。当前窗口登录用的那把不能删；密码登录已关闭时，也不能删某个用户的最后一把公钥。
- **关闭或打开密码登录**：关闭后只能用密钥登录，暴力猜密码的攻击全部失效。只有当前窗口是用密钥登录的才允许关闭，避免把自己锁在外面；已经连着的窗口不受影响。设置写在 `/etc/ssh/sshd_config.d/00-vpsfw-auth.conf`，会优先于服务商镜像自带的配置生效；改完先检查配置、重载 SSH 并确认生效，失败自动恢复。

建议顺序：先在自己电脑上用 `ssh-keygen -t ed25519` 生成密钥，在菜单 11 里添加公钥，新开窗口用密钥登录成功后，再在那个窗口里关闭密码登录。

## 命令行仍然可用

```bash
# 初始化；这里填现有 SSH 端口，不会更改监听
bash vpsfw.sh --ssh-port 2222

# TCP、UDP 分别添加，或使用 both
bash vpsfw.sh ports add 41863,59327 both
bash vpsfw.sh ports delete 41863 tcp
bash vpsfw.sh ports list

# 范围、指定来源、替换端口
bash vpsfw.sh ports add 8000:8010 tcp
bash vpsfw.sh ports add 5432 tcp 192.0.2.8
bash vpsfw.sh ports add 8443 tcp 2001:db8::/64
bash vpsfw.sh ports delete 5432 tcp 192.0.2.8
bash vpsfw.sh ports change 41863 53681 tcp

# 真正修改 SSH 端口：仍分开启新端口和确认两步
bash vpsfw.sh ssh change 38217
bash vpsfw.sh ssh finish
bash vpsfw.sh ssh rollback

# 查看状态 / 同步 Fail2ban / 最近 7 天的 SSH 登录记录
bash vpsfw.sh status
bash vpsfw.sh sync
bash vpsfw.sh logins 7

# 修改密码 / 管理公钥 / 关闭或打开密码登录
bash vpsfw.sh passwd alice
bash vpsfw.sh keys alice
bash vpsfw.sh password-login off

# 禁止 / 恢复别人 ping 这台服务器
bash vpsfw.sh ping off
bash vpsfw.sh ping on
```

省略协议时默认 **TCP**；需要 TCP 和 UDP 时显式选 `both`，大小写均可。来源默认 `any`，也可填 IPv4、IPv6 或 CIDR 网段。多个端口用逗号分隔，范围用冒号或连字符，例如 `443,8000:8010` 或 `443, 8000-8010`。每项单独建规则，范围须整体删除。

已有的普通入站 TCP/UDP 放行规则直接按端口、协议和来源匹配，无需先标记或接管。原注释不影响管理；新增规则统一使用 `VPS TCP/UDP` 注释。脚本不自动删除出站、路由、网卡绑定、应用配置名称或其他复杂规则。它们仍会显示在全部规则列表中。

普通端口操作会保护当前 SSH 连接、SSH 配置端口、实际 SSH 监听和带 SSH 注释的精确匹配规则；修改 SSH 入口使用菜单 8。UDP 可以使用与 SSH TCP 相同的端口号。批量操作先校验所有输入，再修改；替换端口时先完成新规则添加，添加失败不会删除旧规则。

删除某条规则不保证端口完全关闭：已有的大范围放行或其他规则仍可能允许访问。添加来源限制也不会自动撤销原来的公网放行规则，缩小访问范围时需删除旧的 `any` 规则。遇到这两种情况，脚本会在操作结束时列出仍然生效的那几条规则。放行端口不等于程序正在监听，服务商安全组仍需对应配置。

规则语法依据 [Debian UFW 手册](https://manpages.debian.org/trixie/ufw/ufw.8.en.html)。

## 更新脚本

再次执行一键安装命令即可更新 `/usr/local/bin/vpsfw` 并打开菜单。安装脚本会先查询 `main` 分支的最新提交，再按提交下载，推送后一分钟内就能装到新版本，不受 GitHub 下载地址 5 分钟缓存的影响。更新脚本本身不会重新初始化或修改现有规则。旧版应用专用命令已移除，统一使用 `ports add/delete/change/list`；旧规则保持原样且可直接管理。

## 备份及恢复入口

每次操作成功后自动清理旧备份，只保留最近一次。SSH 迁移尚未确认时，额外保留迁移前的原始备份；失败操作不会触发清理。Git 历史不受影响。

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

已完成 Bash 语法检查、隔离文件下的真实 OpenSSH 配置检查，以及端口管理、双端口迁移、会话确认、重载失败回退的模拟测试。另在带 systemd 的 Debian 13 容器里，通过真实 SSH 登录（root 和 sudo 普通用户）跑通了空规则初始化、重复初始化、菜单增删改端口、SSH 迁移确认与回退、防火墙开关。尚未在真实 VPS 上验证。
