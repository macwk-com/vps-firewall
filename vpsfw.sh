#!/usr/bin/env bash
# VPS Firewall — Debian 13, directly installed services.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C.UTF-8
umask 077

die() { printf '\n错误：%s\n' "$*" >&2; exit 1; }
cancel() { printf '已取消%s。\n' "${1:+，$1}"; exit 0; }
# Prompt with line editing (arrow keys work) and trim surrounding spaces. Returns 1 on EOF.
ask() {
    local __value
    IFS= read -e -r -p "$2" __value || return 1
    __value=${__value#"${__value%%[![:space:]]*}"}
    __value=${__value%"${__value##*[![:space:]]}"}
    printf -v "$1" '%s' "$__value"
}
# confirm 问题 [y|n]：y/yes/是 表示同意，回车取默认值。
confirm() {
    local reply default=${2:-n} hint='[y/N]'
    [[ $default == n ]] || hint='[Y/n]'
    ask reply "$1 $hint " || return 1
    reply=$(printf '%s' "${reply:-$default}" | tr '[:upper:]' '[:lower:]')
    [[ $reply == y || $reply == yes || $reply == 是 ]]
}
usage() {
    cat <<'HELP'
VPS Firewall — Debian 13 服务器安全与端口管理
用法：
  vpsfw                              # 彩色菜单
  vpsfw install                      # 初始化 UFW + Fail2ban
  vpsfw --ssh-port 34968              # 使用现有 SSH 端口初始化
  vpsfw ports list                   # 已保存规则及生效状态
  vpsfw ports add 443,8000:8010 tcp    # 单端口、范围、逗号列表
  vpsfw ports add 5432 tcp 192.0.2.8  # 只允许指定来源
  vpsfw ports delete 5432 tcp 192.0.2.8
  vpsfw ports change 443 8443 tcp     # 先放行新端口，再删除旧规则
  vpsfw status
  vpsfw ssh change 38217             # 开启新旧双端口并同步防护
  vpsfw ssh finish                   # 新端口登录后关闭旧入口
  vpsfw ssh rollback
  vpsfw sync                         # 同步 Fail2ban SSH 端口
  vpsfw logins 7                     # 最近 7 天的 SSH 登录记录
  vpsfw passwd [用户]                # 修改登录密码
  vpsfw keys [用户]                  # 查看、添加、删除 SSH 公钥
  vpsfw password-login off|on        # 关闭或打开 SSH 密码登录
  vpsfw ping off|on                  # 禁止或恢复别人 ping 这台服务器
  vpsfw firewall enable|disable
  vpsfw help                         # 显示本帮助

ports add/delete 端口列表 [tcp|udp|both] [来源IP/CIDR|any]
ports change 旧端口或范围 新端口或范围 [tcp|udp|both] [来源IP/CIDR|any]
默认协议 tcp，默认来源 any（所有来源）；范围写 8000:8010 或 8000-8010。
删除/替换按端口、协议和来源精确匹配普通入站放行规则，无需专用标记。
范围规则须整体删除；SSH 入口通过专用菜单管理。
初始化仅放行 SSH，其他端口通过端口管理添加。保留已有 UFW 规则。
适用 Debian 13 宿主机入站流量；不管理应用、容器映射和路由转发。
SSH 迁移仅支持标准 ssh.service，保留新旧入口直到新会话确认。
HELP
}
valid_port() {
    [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 ))
}
valid_spec() {
    local first=${1%%:*} last=${1##*:}
    [[ $1 =~ ^[0-9]+(:[0-9]+)?$ ]] && valid_port "$first" && valid_port "$last" && (( 10#$first <= 10#$last ))
}
# Tolerate spaces, full-width commas and 8000-8010 style ranges.
clean_ports() {
    local v=${1//，/,}
    v=${v//[[:space:]]/}
    printf '%s' "${v//-/:}"
}
parse_ports() {
    local list port existing
    list=$(clean_ports "$1")
    [[ $list =~ ^[0-9:,]+$ && $list != *, && $list != ,* && $list != *,,* ]] || die "端口格式不对：$1。示例：443 或 443,8000-8010"
    local raw=()
    IFS=, read -r -a raw <<< "$list"
    ports=()
    for port in "${raw[@]}"; do
        valid_spec "$port" || die "端口 ${port//:/-} 不对：端口号是 1 到 65535，范围要从小到大，例如 8000-8010。"
        [[ ${port%%:*} != "${port##*:}" ]] || port=${port%%:*}
        local duplicate=0
        for existing in ${ports[@]+"${ports[@]}"}; do [[ $port != "$existing" ]] || duplicate=1; done
        (( duplicate )) || ports+=("$port")
    done
}
normalize_source() {
    python3 - "$1" <<'PYSOURCE'
import ipaddress,sys
s=sys.argv[1].strip()
if s.lower() in ('','any'): print('any')
else:
    try:
        n=ipaddress.ip_network(s,strict=True)
        # Explicit /0 stays address-family-specific, unlike 'any'.
        print(str(n.network_address) if n.prefixlen==n.max_prefixlen else str(n))
    except ValueError:
        try: hint=f'，应写成 {ipaddress.ip_network(s,strict=False)}'
        except ValueError: hint='，例如 192.0.2.8 或 192.0.2.0/24'
        raise SystemExit(f'来源 {s} 不是有效的 IP 或网段{hint}')
PYSOURCE
}
load_rules() { rules=$(ufw show added); }
# Parse only simple inbound allow rules. No eval or execution of rule text.
# `rule_info --list` prints them as port<TAB>proto<TAB>source<TAB>comment;
# `rule_info --other` prints the remaining rule lines unchanged;
# `rule_info --cover` prints port<TAB>proto<TAB>source for every port rule, including port lists
# such as 80,443 and rules without a protocol (proto "any"), to tell whether a port is reachable;
# `rule_info 端口 协议 来源` prints the matching rule's comment (1 = none, 2 = ambiguous).
rule_info() {
    printf '%s\n' "$rules" | python3 -c '
import shlex,sys,ipaddress,re
def norm(s):
    if s=="any": return s
    n=ipaddress.ip_network(s,strict=False)
    return str(n.network_address) if n.prefixlen==n.max_prefixlen else str(n)
def parse(line):
    t=shlex.split(line)
    if t[:2]!=["ufw","allow"]: return None
    t=t[2:]; comment=""
    if "comment" in t:
        i=t.index("comment")
        if len(t)!=i+2: return None
        comment=t[i+1]; t=t[:i]
    if t[:1]==["in"]: t=t[1:]
    if len(t)==1 and "/" not in t[0]:
        rp,rproto,src=t[0],"any","any"
    elif len(t)==1 and "/" in t[0]:
        rp,rproto=t[0].split("/",1); src="any"
    else:
        fields={}; i=0
        while i<len(t):
            if t[i] not in ("proto","from","to","port") or t[i] in fields or i+1>=len(t): break
            fields[t[i]]=t[i+1]; i+=2
        if i!=len(t) or fields.get("to","any")!="any": return None
        if "port" not in fields or "proto" not in fields: return None
        # Do not confuse a source port with a destination port.
        if "to" not in t or t.index("port")<t.index("to"): return None
        rp=fields["port"]; rproto=fields["proto"]; src=fields.get("from","any")
    return rp,rproto,norm(src),comment
def listable(row):
    return row and re.fullmatch(r"\d+(:\d+)?",row[0]) and row[1] in ("tcp","udp")
rows=[]; other=[]
for line in sys.stdin:
    if not line.startswith("ufw "): continue
    try: row=parse(line)
    except ValueError: row=None
    if row: rows.append(row)
    if not listable(row): other.append(line.rstrip("\n"))
if sys.argv[1]=="--list":
    for row in rows:
        if listable(row): print("\t".join(x.replace("\t"," ") for x in row))
    sys.exit(0)
if sys.argv[1]=="--cover":
    for row in rows:
        if re.fullmatch(r"[\d:,]+",row[0]): print("\t".join(row[:3]))
    sys.exit(0)
if sys.argv[1]=="--other":
    if other: print("\n".join(other))
    sys.exit(0)
matches=[row[3] for row in rows if row[:3]==tuple(sys.argv[1:4])]
if len(matches)>1:
    print("精确匹配规则不唯一，请先用 ufw show added 检查",file=sys.stderr); sys.exit(2)
if not matches: sys.exit(1)
print(matches[0])
' "$@"
}
existing_rule() {
    rule_info "$1" "$2" "${3:-any}" >/dev/null
}
# Remaining simple rules of the protocol that open any part of the port or range.
covering_rules() {
    local first=${1%%:*} last=${1##*:} proto=$2 only_source=${3:-} rp rproto rsource rcomment
    while IFS=$'\t' read -r rp rproto rsource rcomment; do
        [[ $rproto == "$proto" ]] || continue
        [[ -z $only_source || $rsource == "$only_source" ]] || continue
        (( 10#${rp%%:*} <= 10#$last && 10#${rp##*:} >= 10#$first )) || continue
        printf '      %s/%s  来源 %s\n' "$rp" "$rproto" "$(source_label "$rsource")"
    done < <(rule_info --list)
}
source_label() { if [[ $1 == any ]]; then printf '所有来源'; else printf '%s' "$1"; fi; }
proto_label() {
    case "$1" in tcp) printf 'TCP' ;; udp) printf 'UDP' ;; *) printf 'TCP+UDP' ;; esac
}
check_ssh_collision() {
    local spec=$1 proto=${2:-tcp} first=${1%%:*} last=${1##*:} current p listeners
    [[ $proto == udp ]] && return 0
    current=$(ssh_ports) || die '无法读取 SSH 配置，暂不修改 TCP 规则。'
    current="$current,${session_port:-},${ssh_port:-}"
    local protected=()
    IFS=, read -r -a protected <<< "$current"
    for p in "${protected[@]}"; do
        [[ -n $p ]] || continue
        if (( 10#$p >= 10#$first && 10#$p <= 10#$last )); then
            [[ $spec == *:* ]] || die "$spec 是 SSH 端口，请用菜单 8「修改 SSH 端口」管理。"
            die "端口范围 ${spec/:/-} 包含 SSH 端口 ${p}，请拆开填写，SSH 端口用菜单 8 管理。"
        fi
    done
    listeners=$(ss -H -lntp "sport >= :$first and sport <= :$last") || die '无法检查实际监听端口。'
    [[ $listeners != *'"sshd"'* && $listeners != *'"sshd-session"'* ]] || die "端口 ${spec/:/-} 正由 SSH 使用，请用菜单 8 管理。"
}
port_rule() {
    local op=$1 port=$2 proto=$3 source=$4
    local args=()
    [[ $op != delete ]] || args+=(--force delete)
    args+=(allow)
    if [[ $source == any ]]; then args+=("$port/$proto")
    else args+=(from "$source" to any port "$port" proto "$proto"); fi
    if [[ $op != delete ]]; then
        if [[ $proto == tcp ]]; then args+=(comment 'VPS TCP'); else args+=(comment 'VPS UDP'); fi
    fi
    ufw "${args[@]}" >/dev/null
}
# `ufw insert 1` fails on an empty rule set (fresh server), so fall back to a plain allow.
allow_ssh() {
    ufw insert 1 allow "$1/tcp" comment 'SSH' >/dev/null 2>&1 || ufw allow "$1/tcp" comment 'SSH' >/dev/null
}
list_ports() {
    printf '\n── 所有已保存规则 ──\n%s\n' "$rules"
    printf '\n── 实际防火墙状态 ──\n'
    ufw status numbered
}
backup_ufw() {
    backup_dir=$(mktemp -d /var/backups/vps-security.XXXXXXXX)
    cp -a /etc/ufw "$backup_dir/ufw"
    cp -a /etc/default/ufw "$backup_dir/ufw-default"
    printf '原 UFW 配置备份：%s\n' "$backup_dir"
}

# Keep the last successful operation's backup; an unconfirmed SSH migration pins its original backup.
prune_backups() {
    python3 - "${backup_dir:-}" /var/backups /var/lib/vps-security/ssh-pending <<'PYBACKUP' || printf '旧备份清理失败，已保留，请检查 /var/backups。\n' >&2
import sys,pathlib,re,shutil
current,root,pending=map(pathlib.Path,sys.argv[1:])
if not current.is_dir() or current.parent!=root:
    raise SystemExit('没有有效的本次备份，跳过清理')
keep={current}
if pending.exists():
    lines=pending.read_text().splitlines()
    if len(lines)!=3: raise SystemExit('待确认迁移状态异常，不清理备份')
    original=pathlib.Path(lines[0])
    if not original.is_dir(): raise SystemExit('迁移原备份缺失，不清理备份')
    keep.add(original)
for p in root.iterdir():
    if p in keep or p.is_symlink() or not p.is_dir(): continue
    if not re.fullmatch(r'vps-security(?:-ssh)?\.[A-Za-z0-9]{8}',p.name): continue
    if (p/'ssh-files.json').is_file() or ((p/'ufw').is_dir() and (p/'ufw-default').is_file()):
        shutil.rmtree(p)
PYBACKUP
}

# SSH changes are transactions. Keep the previous listener until a new-port session confirms.
STATE_DIR=/var/lib/vps-security
PENDING_FILE=$STATE_DIR/ssh-pending
SELF=$(readlink -f "${BASH_SOURCE[0]}")

need_tools() {
    local cmd
    for cmd in ufw fail2ban-client python3 ss sshd; do
        command -v "$cmd" >/dev/null || die '还没有初始化：请先在菜单选 1，或运行 vpsfw install。'
    done
}
# sudo/su drop SSH_CONNECTION; recover it from the nearest ancestor process that still has it.
ssh_connection() {
    local pid=$$ conn
    if [[ -n ${SSH_CONNECTION:-} ]]; then printf '%s\n' "$SSH_CONNECTION"; return 0; fi
    while [[ $pid =~ ^[0-9]+$ ]] && (( pid > 1 )); do
        conn=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p') || conn=''
        if [[ -n $conn ]]; then printf '%s\n' "$conn"; return 0; fi
        pid=$(awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null) || return 0
    done
}
ssh_ports() { sshd -T | awk '$1 == "port" {print $2}' | sort -nu | paste -sd, -; }
wait_f2b() {
    local n
    for ((n=0;n<30;n++)); do
        if fail2ban-client status sshd >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    journalctl -u fail2ban -n 30 --no-pager >&2 || true
    return 1
}
write_f2b() {
    local target_ports=$1
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/sshd.local <<EOF || return 1
[sshd]
enabled = true
filter = sshd
port = $target_ports
backend = systemd
maxretry = 5
findtime = 5m
bantime = 10m
banaction = nftables-multiport
action = nftables-multiport[name=sshd, port="$target_ports", protocol=tcp]
ignoreip = 127.0.0.1/8 ::1
EOF
    local out
    out=$(fail2ban-client -t 2>&1) || { printf '%s\n' "$out" >&2; return 1; }
}
# Restrict automated rewrites to standard Debian includes. Snapshot exactly the files edited.
ssh_config_files() {
    python3 - "$@" <<'PY'
import sys, pathlib, re, json, base64, os, tempfile, shlex
mode, backup = sys.argv[1:3]
main = pathlib.Path('/etc/ssh/sshd_config')
manifest = pathlib.Path(backup) / 'ssh-files.json'
def replace(p, content, permissions):
    fd, name = tempfile.mkstemp(dir=p.parent, prefix='.vps-security-')
    try:
        with os.fdopen(fd, 'wb') as f: f.write(content)
        os.chmod(name, permissions)
        os.replace(name, p)
    finally:
        if os.path.exists(name): os.unlink(name)
if mode == 'restore':
    for item in json.loads(manifest.read_text()):
        replace(pathlib.Path(item['path']), base64.b64decode(item['data']), item['mode'])
    sys.exit(0)
files = [main] + sorted(pathlib.Path('/etc/ssh/sshd_config.d').glob('*.conf'))
items = []
for p in files:
    if p.is_symlink() or not p.is_file(): raise SystemExit(f'不自动修改软链接或特殊文件：{p}')
    data = p.read_bytes()
    text = data.decode()
    for line in text.splitlines():
        words = shlex.split(line, comments=True)
        if not words: continue
        key = words[0].lower()
        if key == 'include' and not (p == main and words[1:] == ['/etc/ssh/sshd_config.d/*.conf']):
            raise SystemExit(f'发现非标准 Include，已停止：{p}: {line}')
        if key == 'listenaddress':
            raise SystemExit('存在自定义 ListenAddress，请先人工确认地址绑定；未修改 SSH。')
    items.append({'path':str(p), 'data':base64.b64encode(data).decode(), 'mode':p.stat().st_mode & 0o777})
if mode == 'snapshot':
    manifest.write_text(json.dumps(items))
elif mode == 'edit':
    ports = sys.argv[3].split(',')
    if not ports or any(not v.isdigit() or not 1 <= int(v) <= 65535 for v in ports):
        raise SystemExit('无效端口')
    for p in files[1:] + [main]:
        text = p.read_text()
        text = re.sub(r'^# BEGIN VPS SECURITY PORTS\n.*?^# END VPS SECURITY PORTS\n?', '', text, flags=re.M|re.S)
        text = re.sub(r'^(\s*Port\s+.*)$', r'# VPS security: previous \1', text, flags=re.M|re.I)
        if p == main:
            text = '# BEGIN VPS SECURITY PORTS\n' + ''.join('Port '+v+'\n' for v in ports) + '# END VPS SECURITY PORTS\n' + text
        replace(p, text.encode(), p.stat().st_mode & 0o777)
else:
    raise SystemExit('未知 SSH 配置操作')
PY
}
ssh_preflight() {
    need_tools
    [[ ! -e $PENDING_FILE || ${1:-} == pending ]] || die '有尚未完成的 SSH 迁移，请先确认或回退。'
    if systemctl is-active --quiet ssh.socket || systemctl is-enabled --quiet ssh.socket; then
        die '检测到 ssh.socket 激活模式。脚本不会自动切换服务模式，SSH 配置未修改。'
    fi
    systemctl is-active --quiet ssh.service || die 'ssh.service 没有运行。'
    sshd -t
    local start environment
    start=$(systemctl cat ssh.service | awk '/^ExecStart=./ {line=$0} END {print line}')
    [[ $start == 'ExecStart=/usr/sbin/sshd -D $SSHD_OPTS' || $start == 'ExecStart=/usr/sbin/sshd -D' ]] || die 'SSH 使用自定义启动命令，无法安全自动改端口。'
    environment=$(systemctl show ssh.service -p Environment --value)
    [[ $environment != *SSHD_OPTS=* ]] || die 'SSH 服务有额外 SSHD_OPTS 环境配置，请先人工检查。'
    python3 - <<'PY'
import pathlib, shlex
p=pathlib.Path('/etc/default/ssh')
if p.exists():
    for line in p.read_text().splitlines():
        words=shlex.split(line, comments=True)
        if not words: continue
        if words[0] == 'export': words=words[1:]
        for word in words:
            if word.startswith('SSHD_OPTS=') and word != 'SSHD_OPTS=':
                raise SystemExit('存在非空 SSHD_OPTS，自定义 SSH 启动配置需人工处理。')
PY
}
ssh_snapshot() {
    backup_dir=$(mktemp -d /var/backups/vps-security-ssh.XXXXXXXX)
    ssh_config_files snapshot "$backup_dir"
    if [[ -e /etc/fail2ban/jail.d/sshd.local ]]; then
        cp -a /etc/fail2ban/jail.d/sshd.local "$backup_dir/sshd.local"
    else
        touch "$backup_dir/no-jail"
    fi
    cp -a /etc/ufw "$backup_dir/ufw"
    printf '修改前备份：%s\n' "$backup_dir"
}
restore_ssh_backup() {
    local source=$1
    ssh_config_files restore "$source" || return 1
    if [[ -e $source/no-jail ]]; then
        rm -f /etc/fail2ban/jail.d/sshd.local || return 1
    else
        cp -a "$source/sshd.local" /etc/fail2ban/jail.d/sshd.local || return 1
    fi
    sshd -t || return 1
    systemctl reload ssh.service || return 1
    systemctl restart fail2ban || return 1
    wait_f2b
}
transaction_exit() {
    local code=$?
    trap - EXIT INT TERM
    if [[ ${transaction_active:-0} == 1 ]]; then
        printf '\n迁移未完成，正在恢复 SSH 和 Fail2ban 配置……\n' >&2
        if ! restore_ssh_backup "$transaction_backup"; then
            printf '自动恢复失败，请使用服务商控制台。备份：%s\n' "$transaction_backup" >&2
        fi
        printf '为避免锁定，新增 UFW 放行规则暂时保留。\n' >&2
    fi
    exit "$code"
}
start_transaction() {
    transaction_backup=$backup_dir
    transaction_active=1
    trap transaction_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}
end_transaction() { transaction_active=0; trap - EXIT INT TERM; }
verify_ssh_ports() {
    local expected=$1 actual p n
    actual=$(ssh_ports)
    expected=$(tr ',' '\n' <<< "$expected" | sort -nu | paste -sd, -)
    [[ $actual == "$expected" ]] || die "SSH 生效配置端口异常：${actual}；期望：$expected"
    IFS=, read -r -a check_ports <<< "$expected"
    for p in "${check_ports[@]}"; do
        for ((n=0;n<10;n++)); do
            if [[ -n $(ss -H -lnt "sport = :$p") ]]; then break; fi
            sleep 1
        done
        (( n < 10 )) || die "新端口 $p 未成功监听，触发恢复。"
    done
}
apply_ssh_ports() {
    local target_ports=$1 p
    IFS=, read -r -a target_array <<< "$target_ports"
    for p in "${target_array[@]}"; do
        allow_ssh "$p"
    done
    ssh_config_files edit "$backup_dir" "$target_ports"
    sshd -t
    write_f2b "$target_ports"
    systemctl reload ssh.service
    verify_ssh_ports "$target_ports"
    systemctl enable --quiet fail2ban
    systemctl restart fail2ban
    wait_f2b
    # A later user .local override must not silently prevent synchronization.
    local effective
    effective=$(fail2ban-client get sshd action nftables-multiport port)
    [[ $effective == "$target_ports" ]] || die "Fail2ban 实际端口 $effective 与目标不符，请检查其他覆盖配置。"
}
read_pending() {
    [[ -f $PENDING_FILE ]] || die '没有待确认的 SSH 迁移。'
    pending=()
    local line
    while IFS= read -r line; do pending+=("$line"); done < "$PENDING_FILE"
    (( ${#pending[@]} == 3 )) || die '迁移状态文件异常。'
    pending_backup=${pending[0]}; pending_old=${pending[1]}; pending_new=${pending[2]}
    [[ $pending_backup == /var/backups/vps-security-ssh.* && -f $pending_backup/ssh-files.json ]] || die '迁移备份不存在。'
    valid_port "$pending_new" || die '迁移状态端口无效。'
    parse_ports "$pending_old"
}
# The exact command to test a new SSH port from the user's own computer.
# Behind cloud NAT the server only sees its private address, so fall back to a placeholder.
ssh_login_hint() {
    local host=服务器IP
    if [[ -n ${server_addr:-} ]] && python3 -c 'import ipaddress,sys; sys.exit(not ipaddress.ip_address(sys.argv[1]).is_global)' "$server_addr" 2>/dev/null; then
        host=$server_addr
    fi
    printf 'ssh -p %s %s@%s' "$1" "${2:-${SUDO_USER:-$(logname 2>/dev/null || id -un)}}" "$host"
}
ssh_change() {
    local new=$1 old combined comment lookup_status
    valid_port "$new" || die '请输入 1 到 65535 的端口。'
    ssh_preflight
    old=$(ssh_ports)
    [[ ,$old, != *,$new,* ]] || die '该端口已经是 SSH 监听端口。'
    [[ -z $(ss -H -lnt "sport = :$new") ]] || die '新 TCP 端口已被其他程序使用。'
    load_rules
    if comment=$(rule_info "$new" tcp any); then
        [[ $comment == SSH ]] || die '新端口已有普通 TCP 放行规则，请先确认用途并删除该规则。'
    else
        lookup_status=$?
        (( lookup_status == 1 )) || die '新端口规则不明确，请先检查。'
    fi
    printf '\nSSH 端口：%s → %s\n' "$old" "$new"
    printf '迁移分两步：先让新旧端口同时可用；你用新端口登录成功后，再关闭旧端口。\n'
    printf '开始前请确认：服务商安全组（云防火墙）已放行 %s/TCP，并且不要关闭当前窗口。\n\n' "$new"
    confirm '开始第一步？' || cancel '没有修改任何配置'
    ssh_snapshot
    start_transaction
    combined=$(printf '%s,%s\n' "$old" "$new" | tr ',' '\n' | sort -nu | paste -sd, -)
    apply_ssh_ports "$combined"
    mkdir -p "$STATE_DIR"
    printf '%s\n%s\n%s\n' "$backup_dir" "$old" "$new" > "$PENDING_FILE.tmp"
    mv "$PENDING_FILE.tmp" "$PENDING_FILE"
    end_transaction
    prune_backups
    printf '\n第一步完成：新端口 %s 已开始监听，旧端口 %s 仍然可用，Fail2ban 同时保护两者。\n\n' "$new" "$old"
    printf '下一步：保留当前窗口，在你自己电脑上新开一个终端执行：\n\n    %s\n\n' "$(ssh_login_hint "$new")"
    printf '登录成功后，在新窗口里运行 vpsfw，选择 8，再选「确认迁移」。\n'
    printf '如果新端口连不上，回到当前窗口选择 8，再选「回退迁移」。\n'
}
ssh_finish() {
    read_pending
    if [[ ${session_port:-} != "$pending_new" ]]; then
        printf '\n当前窗口是通过 %s 连接的，不能在这里确认。\n' "${session_port:-控制台}" >&2
        printf '请先用新端口登录（%s），在新窗口里选择 8 确认。\n' "$(ssh_login_hint "$pending_new")" >&2
        printf '这样可以证明新端口确实能连上，避免把自己锁在外面。\n' >&2
        exit 1
    fi
    ssh_preflight pending
    printf '当前窗口已通过新端口 %s 登录，接下来关闭旧端口 %s。\n' "$pending_new" "$pending_old"
    confirm '确认完成迁移？' || cancel '新旧端口继续同时可用'
    ssh_snapshot
    start_transaction
    apply_ssh_ports "$pending_new"
    # Commit before optional rule cleanup; a cleanup failure must not reopen old SSH listeners.
    end_transaction
    rm -f "$PENDING_FILE"
    load_rules
    local p
    IFS=, read -r -a old_array <<< "$pending_old"
    for p in "${old_array[@]}"; do
        if [[ $'\n'$rules$'\n' == *$'\n'"ufw allow $p/tcp comment 'SSH'"$'\n'* ]]; then
            ufw --force delete allow "$p/tcp" comment 'SSH' >/dev/null
        fi
    done
    prune_backups
    printf '\n迁移完成：SSH 只监听 %s，Fail2ban 已同步，旧端口 %s 已关闭。\n' "$pending_new" "$pending_old"
    printf '记得在服务商安全组里删除旧端口 %s 的放行。\n' "$pending_old"
}
ssh_rollback() {
    read_pending
    printf 'SSH 将恢复为迁移前的端口 %s，新端口 %s 停止监听，迁移时为它添加的防火墙放行也一并删除。\n' "$pending_old" "$pending_new"
    confirm '确认回退？' || cancel
    restore_ssh_backup "$pending_backup"
    rm -f "$PENDING_FILE"
    backup_dir=$pending_backup
    printf '已回退：SSH 和 Fail2ban 恢复为迁移前的配置（端口 %s）。\n' "$pending_old"
    # Cleanup only after SSH is back on the old port; a rule that predates the migration stays.
    load_rules
    if [[ $'\n'$rules$'\n' != *$'\n'"ufw allow $pending_new/tcp comment 'SSH'"$'\n'* ]]; then
        :
    elif grep -qs "^### tuple ### allow tcp $pending_new " "$pending_backup/ufw/user.rules" "$pending_backup/ufw/user6.rules"; then
        printf '%s/tcp 的放行规则在迁移前就已存在，保留不动。\n' "$pending_new"
    elif ! (verify_ssh_ports "$pending_old") 2>/dev/null; then
        printf '旧端口 %s 没有确认恢复监听，%s/tcp 的放行规则先保留，请检查后手动处理。\n' "$pending_old" "$pending_new" >&2
    elif ufw --force delete allow "$pending_new/tcp" comment 'SSH' >/dev/null; then
        printf '已删除 %s/tcp 的防火墙放行；服务商安全组里的这条放行也可以删掉。\n' "$pending_new"
    else
        printf '删除 %s/tcp 的防火墙放行失败，请手动执行：ufw delete allow %s/tcp\n' "$pending_new" "$pending_new" >&2
    fi
    prune_backups
}
# Colors only on a real terminal; NO_COLOR turns them off.
set_colors() {
    c_ok='' c_warn='' c_err='' c_dim='' c_head='' c_off=''
    if [[ -t 1 && ${TERM:-dumb} != dumb && ${NO_COLOR+x} != x ]]; then
        c_ok=$'\033[32m' c_warn=$'\033[33m' c_err=$'\033[31m'
        c_dim=$'\033[90m' c_head=$'\033[1;36m' c_off=$'\033[0m'
    fi
}
section() { printf '\n  %s%s%s\n' "$c_head" "$1" "$c_off"; }
# status_row 标签 值 值的颜色 说明
status_row() {
    printf '  %s%s%s%s  %s%s%s\n' "$(pad "$1" 10)" "$3" "$(pad "$2" 12)" "$c_off" "$c_dim" "${4:-}" "$c_off"
}
human_seconds() {
    local s=$1
    if [[ ! $s =~ ^-?[0-9]+$ ]]; then printf '%s' "$s"
    elif (( s < 0 )); then printf '永久'
    elif (( s >= 3600 && s % 3600 == 0 )); then printf '%s 小时' $((s / 3600))
    elif (( s >= 60 && s % 60 == 0 )); then printf '%s 分钟' $((s / 60))
    else printf '%s 秒' "$s"; fi
}
# Read the sshd jail into f2b_state / f2b_color / f2b_status (empty when not running).
read_f2b() {
    f2b_status=''
    if ! command -v fail2ban-client >/dev/null; then
        f2b_state='● 未安装'; f2b_color=$c_err
    elif f2b_status=$(fail2ban-client status sshd 2>/dev/null); then
        f2b_state='● 保护中'; f2b_color=$c_ok
    else
        f2b_state='● 未运行'; f2b_color=$c_warn; f2b_status=''
    fi
}
# One "Name:<TAB>value" field of `fail2ban-client status sshd`.
f2b_field() { printf '%s\n' "$f2b_status" | sed -n "s/.*$1:[[:space:]]*//p"; }
print_banned() {
    local list total
    list=$(f2b_field 'Banned IP list')
    if [[ -z $list ]]; then printf '  %s无%s\n' "$c_dim" "$c_off"; return 0; fi
    total=$(wc -w <<< "$list")
    printf '%s\n' $list | awk 'NR <= 30 {
        if (line != "" && length(line) + length($1) > 70) { print line; line = "" }
        line = line (line == "" ? "  " : "   ") $1
    } END { if (line != "") print line }'
    (( total <= 30 )) || printf '  %s……共 %s 个，只显示前 30 个%s\n' "$c_dim" "$total" "$c_off"
}
show_status() {
    set_colors
    local raw fw='● 未安装' fw_color=$c_err fw_note='请先初始化（菜单 1）' policy_in policy_out ipv6
    local ssh ssh_color='' ssh_note f2b_note rows others count rp rproto rsource rcomment
    if command -v ufw >/dev/null; then
        raw=$(ufw status 2>/dev/null) || raw=''
        policy_in=$(sed -n 's/^DEFAULT_INPUT_POLICY="\(.*\)"$/\1/p' /etc/default/ufw)
        policy_out=$(sed -n 's/^DEFAULT_OUTPUT_POLICY="\(.*\)"$/\1/p' /etc/default/ufw)
        if grep -q '^IPV6=yes' /etc/default/ufw; then ipv6='IPv6 开启'; else ipv6='IPv6 未开启'; fi
        if [[ $policy_in == ACCEPT ]]; then policy_in='默认放行所有入站'; else policy_in='拒绝未放行的入站'; fi
        if [[ $policy_out == ACCEPT ]]; then policy_out='允许出站'; else policy_out='限制出站'; fi
        case "$raw" in
            'Status: active'*) fw='● 已启用'; fw_color=$c_ok; fw_note="$policy_in · $policy_out · $ipv6" ;;
            'Status: inactive'*) fw='● 未启用'; fw_color=$c_warn; fw_note='下面的规则已保存，启用后才生效（菜单 7）' ;;
            *) fw='● 状态异常'; fw_note='请运行 ufw status 查看' ;;
        esac
    fi
    ssh=$(ssh_ports 2>/dev/null) || ssh=''
    if [[ -f $PENDING_FILE ]]; then ssh_color=$c_warn; ssh_note='迁移待确认：请从新端口登录后选 8'
    elif [[ -n ${session_port:-} ]]; then ssh_note="当前连接 $session_port"
    else ssh_note='当前在控制台'; fi
    read_f2b
    case "$f2b_state" in
        *保护中) f2b_note="封禁中 $(f2b_field 'Currently banned') 个 · 累计 $(f2b_field 'Total banned') 次" ;;
        *未运行) f2b_note='SSH 登录保护没有运行，可在菜单 9 同步' ;;
        *) f2b_note='请先初始化（菜单 1）' ;;
    esac

    section '防护状态'
    status_row 防火墙 "$fw" "$fw_color" "$fw_note"
    status_row SSH "${ssh:-未知}" "$ssh_color" "$ssh_note"
    status_row Fail2ban "$f2b_state" "$f2b_color" "$f2b_note"
    if command -v ufw >/dev/null; then
        ping_state
        case $REPLY in
            blocked) status_row Ping '● 已禁止' "$c_ok" '别人 ping 不通这台服务器' ;;
            allowed) status_row Ping '允许' '' '需要时可在菜单 12 禁止' ;;
            mixed) status_row Ping '● 部分禁止' "$c_warn" 'IPv4 和 IPv6 的设置不一致' ;;
            *) status_row Ping '未知' "$c_warn" 'UFW 的 ping 规则被手动改过' ;;
        esac
    fi

    if command -v ufw >/dev/null; then
        load_rules
        rows=$(rule_info --list); others=$(rule_info --other)
        count=0; [[ -z $rows ]] || count=$(wc -l <<< "$rows")
        section "放行规则（$count 条）"
        if (( count == 0 )); then
            printf '  %s无%s\n' "$c_dim" "$c_off"
        else
            printf '  %s%s%s%s备注%s\n' "$c_dim" "$(pad 端口 12)" "$(pad 协议 6)" "$(pad 来源 20)" "$c_off"
            while IFS=$'\t' read -r rp rproto rsource rcomment; do
                printf '  %s%s%s %s%s%s\n' "$(pad "$rp" 12)" "$(pad "$(proto_label "$rproto")" 6)" \
                    "$(pad "$(source_label "$rsource")" 19)" "$c_dim" "$rcomment" "$c_off"
            done <<< "$rows"
        fi
        if [[ -n $others ]]; then
            section '其他规则（不在本工具管理范围，原样显示）'
            printf '%s\n' "$others" | sed "s/^/  $c_dim/; s/\$/$c_off/"
        fi
    fi
    if [[ -n $f2b_status ]]; then
        section '正在封禁的 IP'
        print_banned
    fi
    printf '\n'
}
# Fail2ban details for menu 11; sets f2b_sync=1 when the jail needs resyncing.
show_f2b() {
    set_colors
    read_f2b
    local ssh ports maxretry findtime bantime
    f2b_sync=0
    ssh=$(ssh_ports 2>/dev/null) || ssh=''
    section 'Fail2ban · SSH 登录保护'
    if [[ -z $f2b_status ]]; then
        if [[ $f2b_state == *未安装 ]]; then
            status_row 状态 "$f2b_state" "$f2b_color" '请先初始化（菜单 1）'
        else
            status_row 状态 "$f2b_state" "$f2b_color" 'SSH 登录保护没有运行'
            f2b_sync=1
        fi
        return 0
    fi
    ports=$(fail2ban-client get sshd action nftables-multiport port 2>/dev/null) || ports=''
    maxretry=$(fail2ban-client get sshd maxretry 2>/dev/null) || maxretry='?'
    findtime=$(fail2ban-client get sshd findtime 2>/dev/null) || findtime='?'
    bantime=$(fail2ban-client get sshd bantime 2>/dev/null) || bantime='?'
    status_row 状态 "$f2b_state" "$f2b_color"
    if [[ -n $ports && $ports == "$ssh" ]]; then
        status_row 保护端口 "$ports" '' '与 SSH 端口一致'
    else
        status_row 保护端口 "${ports:-未知}" "$c_warn" "SSH 实际端口是 ${ssh:-未知}，需要同步"
        f2b_sync=1
    fi
    status_row 封禁条件 "失败 $maxretry 次" '' "$(human_seconds "$findtime")内失败 $maxretry 次，封禁 $(human_seconds "$bantime")"
    status_row 封禁中 "$(f2b_field 'Currently banned') 个 IP" '' "累计封禁 $(f2b_field 'Total banned') 次"
    status_row 近期失败 "$(f2b_field 'Currently failed') 次" '' "统计窗口内还没达到封禁条件的失败登录"
    section '正在封禁的 IP'
    print_banned
}
# SSH logins of the last N days from the journal: successes first, then failures per source IP,
# then how often Fail2ban banned. Read only.
show_logins() {
    local days=${1:-1} banned=''
    set_colors
    command -v journalctl >/dev/null || { printf '\n系统没有 journalctl，读不到 SSH 登录记录。\n'; return 0; }
    if command -v fail2ban-client >/dev/null; then
        banned=$(fail2ban-client status sshd 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p') || banned=''
    fi
    python3 - "$days" "$banned" "$c_ok" "$c_warn" "$c_err" "$c_dim" "$c_head" "$c_off" <<'PY'
import glob, gzip, json, re, subprocess, sys, time, unicodedata
from collections import Counter, defaultdict
days = int(sys.argv[1]); banned = set(sys.argv[2].split())
ok, warn, err, dim, head, off = sys.argv[3:9]
since = time.time() - days * 86400

def width(text):
    return sum(2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in text)
def pad(text, cells):
    return text + ' ' * max(cells - width(text), 1)
def stamp(seconds):
    return time.strftime('%m-%d %H:%M', time.localtime(seconds))
def section(title):
    print(f'\n  {head}{title}{off}')

journal = subprocess.run(['journalctl', '-u', 'ssh.service', '-u', 'sshd.service', '--since', f'{days} days ago',
                          '-o', 'json', '--no-pager'], capture_output=True, text=True).stdout
accepted = re.compile(r'Accepted (\S+) for (\S+) from (\S+) port')
failed = re.compile(r'Failed \S+ for (?:invalid user )?(.*?) from (\S+) port')
invalid = re.compile(r'Invalid user (.*?) from (\S+) port')
closed = re.compile(r'(?:Connection closed|Disconnected) by (?:authenticating|invalid) user (.*?) (\S+) port \d+ \[preauth\]')
# OpenSSH 9.8+ refuses new connections from a source that keeps failing (PerSourcePenalties).
penalty = re.compile(r'drop connection #\d+ from \[(.+?)\]:\d+ on .* penalty: ')
dropped = Counter()
# One sshd-session process is one connection; group its lines so one attempt is counted once.
connections = defaultdict(lambda: {'fails': 0, 'rejected': False})
successes = []
for line in journal.splitlines():
    try: entry = json.loads(line)
    except ValueError: continue
    message = entry.get('MESSAGE')
    if isinstance(message, list): message = bytes(message).decode('utf-8', 'replace')
    if not isinstance(message, str): continue
    when = int(entry.get('__REALTIME_TIMESTAMP', 0)) / 1e6
    if m := penalty.search(message):
        dropped[m.group(1)] += 1
        continue
    conn = connections[(entry.get('_BOOT_ID'), entry.get('_PID'))]
    if m := accepted.search(message):
        method, user, ip = m.groups()
        successes.append((when, user, ip, {'publickey': '密钥', 'password': '密码'}.get(method, method)))
        conn['accepted'] = True
        continue
    for pattern in (failed, invalid, closed):
        if m := pattern.search(message):
            user, ip = m.groups()
            conn.update(ip=ip, user=user, last=when)
            if pattern is failed: conn['fails'] += 1
            else: conn['rejected'] = True
            break

attempts, last, users = Counter(), {}, defaultdict(Counter)
for conn in connections.values():
    if conn.get('accepted') or 'ip' not in conn: continue
    count = conn['fails'] or 1
    attempts[conn['ip']] += count
    users[conn['ip']][conn['user']] += count
    last[conn['ip']] = max(last.get(conn['ip'], 0), conn['last'])

# The IP column is only as wide as the longest address shown.
shown = [ip for _, _, ip, _ in successes[-20:]] + [ip for ip, _ in attempts.most_common(10)]
ip_cells = max([width('来源 IP')] + [width(ip) for ip in shown]) + 3
print(f'\n  {head}SSH 登录记录 · 最近 {days} 天{off}')
section(f'成功登录（{len(successes)} 次）')
if successes:
    print(f"  {dim}{pad('时间', 14)}{pad('用户', 10)}{pad('来源 IP', ip_cells)}方式{off}")
    for when, user, ip, method in sorted(successes, reverse=True)[:20]:
        print(f'  {pad(stamp(when), 14)}{pad(user, 10)}{pad(ip, ip_cells)}{method}')
    if len(successes) > 20: print(f'  {dim}……只显示最近 20 次{off}')
else:
    print(f'  {dim}无{off}')

section(f'失败尝试（{sum(attempts.values())} 次，来自 {len(attempts)} 个 IP）')
if attempts:
    print(f"  {dim}{pad('来源 IP', ip_cells)}{pad('次数', 7)}{pad('最近一次', 14)}{pad('试过的用户名', 26)}状态{off}")
    for ip, count in attempts.most_common(10):
        names = [name for name, _ in users[ip].most_common()]
        tried = '、'.join(names[:3]) + ('…' if len(names) > 3 else '')
        status = f'{ok}● 已封禁{off}' if ip in banned else ''
        print(f'  {pad(ip, ip_cells)}{pad(str(count), 7)}{pad(stamp(last[ip]), 14)}{pad(tried, 26)}{status}')
    if len(attempts) > 10: print(f'  {dim}……按次数只显示前 10 个 IP{off}')
else:
    print(f'  {dim}无{off}')
if dropped:
    print(f'  {dim}另外 sshd 自带的防护直接拒绝了 {sum(dropped.values())} 次连接（{len(dropped)} 个 IP 失败太频繁），这些连接没到登录这一步。{off}')

# logrotate keeps about a month of fail2ban.log: .1 plain, older ones gzipped.
bans, oldest = [], None
for path in glob.glob('/var/log/fail2ban.log*'):
    try:
        with (gzip.open if path.endswith('.gz') else open)(path, 'rt', errors='replace') as log:
            for line in log:
                m = re.match(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)', line)
                if not m: continue
                when = time.mktime(time.strptime(m.group(1), '%Y-%m-%d %H:%M:%S'))
                oldest = when if oldest is None else min(oldest, when)
                if when >= since and (ban := re.search(r'\[sshd\] Ban (\S+)', line)): bans.append(ban.group(1))
    except (OSError, EOFError):
        continue
note = f'（Fail2ban 日志最早只到 {stamp(oldest)}）' if oldest and oldest > since + 86400 else ''
print(f'\n  {dim}Fail2ban 这段时间封禁了 {len(bans)} 次（{len(set(bans))} 个 IP），目前仍在封禁 {len(banned)} 个。{note}{off}\n')
PY
}
menu_logins() {
    local days
    while true; do
        ask days '查看最近几天的记录？[回车 = 1]: ' || return 0
        days=${days:-1}
        [[ ! $days =~ ^[0-9]+$ ]] || (( 10#$days < 1 || 10#$days > 90 )) || break
        printf '请输入 1 到 90 之间的天数。\n'
    done
    show_logins "$((10#$days))"
}
# ── Ping: only the two lines that accept echo requests change; other ICMP (errors, IPv6 neighbour
# discovery) keeps working, and so does pinging out from this server. ──
PING_V4='-A ufw-before-input -p icmp --icmp-type echo-request -j'
PING_V6='-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j'
# ACCEPT or DROP from a rules file, or nothing when the line is missing, duplicated or edited.
ping_rule() {
    local count
    count=$(grep -c -F -x -e "$2 ACCEPT" -e "$2 DROP" "$1" 2>/dev/null || true)
    [[ $count == 1 ]] || return 0
    grep -F -x -e "$2 ACCEPT" -e "$2 DROP" "$1" | awk '{print $NF}'
}
# Sets REPLY to allowed, blocked, mixed or unknown.
ping_state() {
    local v4 v6
    v4=$(ping_rule /etc/ufw/before.rules "$PING_V4"); v6=$(ping_rule /etc/ufw/before6.rules "$PING_V6")
    if [[ $v4 == ACCEPT && $v6 == ACCEPT ]]; then REPLY=allowed
    elif [[ $v4 == DROP && $v6 == DROP ]]; then REPLY=blocked
    elif [[ -n $v4 && -n $v6 ]]; then REPLY=mixed
    else REPLY=unknown; fi
}
ping_switch() {
    local want=$1 target=DROP expected=blocked
    command -v ufw >/dev/null || die '还没有初始化：请先在菜单选 1，或运行 vpsfw install。'
    [[ $want == off ]] || { target=ACCEPT; expected=allowed; }
    ping_state
    [[ $REPLY != unknown ]] || die 'UFW 的 ping 规则被手动改过（/etc/ufw/before.rules 或 before6.rules），无法自动修改。'
    if [[ $REPLY == "$expected" ]]; then
        if [[ $want == off ]]; then printf '服务器本来就不响应 ping。\n'; else printf '服务器本来就响应 ping。\n'; fi
        return 0
    fi
    if [[ $want == off ]]; then
        printf '禁止后，别人 ping 这台服务器会一直超时（IPv4 和 IPv6 都一样）。网站、SSH 等服务照常，服务器自己 ping 别人也不受影响。\n'
        printf '注意：服务商后台或监控工具如果靠 ping 判断在线，可能会显示离线；禁止 ping 只是少暴露一点，端口扫描照样能发现这台服务器。\n'
        confirm '禁止 ping？' y || cancel
    else
        printf '恢复后，别人可以 ping 通这台服务器。\n'
        confirm '允许 ping？' y || cancel
    fi
    backup_ufw
    sed -i "s#^$PING_V4 \(ACCEPT\|DROP\)\$#$PING_V4 $target#" /etc/ufw/before.rules
    sed -i "s#^$PING_V6 \(ACCEPT\|DROP\)\$#$PING_V6 $target#" /etc/ufw/before6.rules
    ping_state
    if [[ $REPLY != "$expected" ]] || { [[ $(ufw status) == 'Status: active'* ]] && ! ufw reload >/dev/null; }; then
        cp -a "$backup_dir/ufw/before.rules" "$backup_dir/ufw/before6.rules" /etc/ufw/
        ufw reload >/dev/null 2>&1 || true
        die '修改没有生效，已恢复原来的设置。'
    fi
    prune_backups
    if [[ $want == off ]]; then printf '已禁止 ping。\n'; else printf '已恢复响应 ping。\n'; fi
    [[ $(ufw status) == 'Status: active'* ]] || printf '防火墙当前未启用，设置已保存，启用后才生效（菜单 7）。\n'
}
menu_ping() {
    command -v ufw >/dev/null || { printf '\n还没有初始化，请先选择 1。\n'; return 0; }
    ping_state
    case $REPLY in
        allowed) printf '\n现在：服务器响应 ping。\n'; bash "$SELF" ping off || true ;;
        blocked) printf '\n现在：服务器不响应 ping。\n'; bash "$SELF" ping on || true ;;
        mixed) printf '\n现在：IPv4 和 IPv6 的设置不一致。\n'; bash "$SELF" ping off || true ;;
        *) printf '\nUFW 的 ping 规则被手动改过，无法自动修改。\n' ;;
    esac
}
# ── SSH login methods: account passwords, public keys and whether password login is allowed. ──
AUTH_CONF=/etc/ssh/sshd_config.d/00-vpsfw-auth.conf

# Effective sshd setting, e.g. sshd_value passwordauthentication.
sshd_value() { sshd -T 2>/dev/null | awk -v key="$1" '$1 == key {print $2}'; }
# Accounts that can log in: root plus regular users with a real shell.
login_users() {
    getent passwd | awk -F: '($3 == 0 || ($3 >= 1000 && $3 < 60000)) && $7 !~ /(nologin|false)$/ {print $1}'
}
is_login_user() { [[ $'\n'$(login_users)$'\n' == *$'\n'"$1"$'\n'* ]]; }
user_home() { getent passwd "$1" | cut -d: -f6; }
# How this SSH connection logged in: sets auth_method, auth_user and auth_key (key fingerprint).
session_auth() {
    auth_method='' auth_user='' auth_key=''
    [[ -n ${client_addr:-} ]] || return 0
    local line
    line=$(journalctl -u ssh.service -u sshd.service -o cat --no-pager 2>/dev/null |
        grep -F -- " from $client_addr port $client_port " | grep '^Accepted ' | tail -n 1) || line=''
    [[ $line =~ ^Accepted\ ([a-z-]+)\ for\ ([^ ]+)\ from ]] || return 0
    auth_method=${BASH_REMATCH[1]}; auth_user=${BASH_REMATCH[2]}
    [[ ! $line =~ (SHA256:[A-Za-z0-9+/]+) ]] || auth_key=${BASH_REMATCH[1]}
}
# Sets REPLY to 有密码（上次修改日期）or 没有密码.
password_state() {
    local fields=()
    read -r -a fields <<< "$(passwd -S "$1" 2>/dev/null)" || true
    if [[ ${fields[1]:-} == P ]]; then REPLY="有密码（${fields[2]:-?} 修改）"; else REPLY='没有密码'; fi
}
# Public keys in an authorized_keys file: list them, check a pasted line, or remove one by number.
key_tool() {
    python3 - "$@" <<'PY'
import os, subprocess, sys, tempfile
op, *args = sys.argv[1:]
def fingerprint(line):
    with tempfile.NamedTemporaryFile('w', suffix='.pub') as f:
        f.write(line + '\n'); f.flush()
        result = subprocess.run(['ssh-keygen', '-l', '-f', f.name], capture_output=True, text=True)
    if result.returncode or not result.stdout.strip(): return None
    _, fp, *rest = result.stdout.split()
    return fp, (rest[-1].strip('()') if rest else '?'), ' '.join(rest[:-1])
def keys(path):
    try: lines = open(path).read().splitlines()
    except FileNotFoundError: lines = []
    return lines, [(i, info) for i, line in enumerate(lines)
                   if line.strip() and not line.lstrip().startswith('#') and (info := fingerprint(line.strip()))]
if op == 'list':
    for number, (_, (fp, kind, comment)) in enumerate(keys(args[0])[1], 1):
        print(number, kind, fp, comment or '-', sep='\t')
elif op == 'check':
    line = args[0].strip()
    if 'PRIVATE KEY' in line:
        raise SystemExit('这是私钥，千万不要放到服务器上。请粘贴 .pub 文件里的那一行（以 ssh-ed25519 或 ssh-rsa 开头）。')
    info = fingerprint(line)
    if not info: raise SystemExit('不是有效的公钥。请粘贴 .pub 文件里完整的一行，例如 ssh-ed25519 AAAA… 备注')
    print(info[0])
elif op == 'remove':
    path, number = args[0], int(args[1])
    lines, found = keys(path)
    del lines[found[number - 1][0]]
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.authorized_keys.')
    with os.fdopen(fd, 'w') as f: f.write(''.join(line + '\n' for line in lines))
    info = os.stat(path); os.chown(tmp, info.st_uid, info.st_gid); os.chmod(tmp, 0o600)
    os.replace(tmp, path)
PY
}
key_count() { { key_tool list "$(user_home "$1")/.ssh/authorized_keys" || true; } | wc -l; }
# Status block of menu 11 for one account.
auth_status() {
    local user=$1 pa root_login how
    set_colors
    pa=$(sshd_value passwordauthentication) || pa=''
    root_login=$(sshd_value permitrootlogin) || root_login=''
    section 'SSH 登录方式'
    if [[ $pa == no ]]; then
        status_row 密码登录 '● 已关闭' "$c_ok" '只能用密钥登录'
    else
        case $root_login in
            yes) how='root 也可以用密码登录' ;;
            no) how='root 不能登录 SSH' ;;
            *) how='root 除外，root 只能用密钥' ;;
        esac
        status_row 密码登录 '● 允许' "$c_warn" "$how"
    fi
    if [[ -z ${client_addr:-} ]]; then how='服务商控制台（不是 SSH 连接）'
    elif [[ $auth_method == publickey ]]; then how="$auth_user，用密钥登录"
    elif [[ -n $auth_method ]]; then how="$auth_user，用密码登录"
    else how='SSH（查不到是怎么登录的）'; fi
    printf '  %s%s\n' "$(pad 当前连接 10)" "$how"
    password_state "$user"
    printf '  %s%s · 公钥 %s 把\n' "$(pad "$user" 10)" "$REPLY" "$(key_count "$user")"
}
# Ask which account to work on; REPLY holds it. Defaults to the account of this connection.
ask_login_user() {
    local default=${auth_user:-${SUDO_USER:-root}} value
    printf '\n可以选的用户：%s\n' "$(login_users | tr '\n' ' ')"
    while true; do
        ask value "$1 [回车 = $default]: " || return 1
        value=${value:-$default}
        if is_login_user "$value"; then REPLY=$value; return 0; fi
        printf '%s 不是可以登录的用户。\n' "$value"
    done
}
change_password() {
    local user=$1 pa root_login state choice pw pw2 generated=0
    set_colors
    is_login_user "$user" || die "$user 不是可以登录的用户。"
    pa=$(sshd_value passwordauthentication) || pa=''
    root_login=$(sshd_value permitrootlogin) || root_login=''
    password_state "$user"; state=$REPLY
    printf '\n修改 %s 的密码（现在：%s）\n' "$user" "$state"
    if [[ $pa == no ]]; then
        printf 'SSH 已关闭密码登录，这个密码只在 sudo、su 和服务商网页控制台里用。\n'
    elif [[ $user == root && $root_login != yes ]]; then
        printf 'root 不能用密码登录 SSH，这个密码只在 su 和服务商网页控制台里用。\n'
    elif [[ $state == 没有密码 ]]; then
        printf '注意：%s 现在没有密码；设置后就能用密码登录 SSH，别人也能对它猜密码。\n' "$user"
    fi
    printf '\n  1) 自己输入\n  2) 生成一个随机强密码\n\n'
    while true; do
        ask choice '请选择 [回车 = 1]: ' || cancel
        choice=${choice:-1}
        [[ $choice != 1 && $choice != 2 ]] || break
        printf '请输入 1 或 2。\n'
    done
    if [[ $choice == 2 ]]; then
        generated=1
        pw=$(python3 -c 'import secrets
a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
print("-".join("".join(secrets.choice(a) for _ in range(5)) for _ in range(4)))')
    else
        # The system accepts any password, so enforce a minimum here.
        while true; do
            IFS= read -r -s -p '新密码（至少 12 位，输入时不显示）: ' pw || cancel; printf '\n'
            if (( ${#pw} < 12 )); then printf '太短了，至少要 12 位。\n'; continue; fi
            if [[ $pw == *"$user"* ]]; then printf '密码里不能包含用户名。\n'; continue; fi
            IFS= read -r -s -p '再输入一次: ' pw2 || cancel; printf '\n'
            [[ $pw != "$pw2" ]] || break
            printf '两次输入的不一样，请重新输入。\n'
        done
    fi
    confirm "确认修改 $user 的密码？" y || cancel '密码没有改'
    # Through stdin only: the password never appears in arguments, history or logs.
    printf '%s:%s\n' "$user" "$pw" | chpasswd || die '修改失败，密码没有改。'
    (( ! generated )) || printf '\n新密码：%s%s%s\n请现在就记下来，脚本不会保存，也不会再显示。\n' "$c_warn" "$pw" "$c_off"
    printf '\n%s 的密码已修改。当前连接和密钥登录都不受影响。\n' "$user"
    if [[ $pa != no && ( $user != root || $root_login == yes ) ]]; then
        printf '如果你用密码登录，先别关当前窗口，新开一个窗口用新密码试一下。\n'
    fi
}
manage_keys() {
    local user=$1 home file group list count choice value fp number line kind comment mark pa port
    set_colors
    is_login_user "$user" || die "$user 不是可以登录的用户。"
    home=$(user_home "$user"); file=$home/.ssh/authorized_keys; group=$(id -gn "$user")
    session_auth
    pa=$(sshd_value passwordauthentication) || pa=''
    list=$(key_tool list "$file") || die "读不了 $file。"
    count=0; [[ -z $list ]] || count=$(wc -l <<< "$list")
    section "$user 的公钥（$count 把）"
    if (( count == 0 )); then
        printf '  %s还没有公钥，这个用户不能用密钥登录。%s\n' "$c_dim" "$c_off"
    else
        printf '  %s%s%s%s备注%s\n' "$c_dim" "$(pad 编号 6)" "$(pad 类型 10)" "$(pad 指纹 22)" "$c_off"
        while IFS=$'\t' read -r number kind fp comment; do
            mark=''
            [[ $user != "$auth_user" || $fp != "$auth_key" ]] || mark="  ${c_ok}● 当前登录用的${c_off}"
            printf '  %s%s%s%s%s\n' "$(pad "$number" 6)" "$(pad "$kind" 10)" "$(pad "${fp:0:19}…" 22)" "$comment" "$mark"
        done <<< "$list"
    fi
    printf '\n  1) 添加公钥\n'
    (( count == 0 )) || printf '  2) 删除公钥\n'
    printf '\n'
    while true; do
        ask choice '请选择（回车返回）: ' && [[ -n $choice ]] || return 0
        [[ $choice != 1 && ( $choice != 2 || count -eq 0 ) ]] || break
        printf '没有这个选项。\n'
    done
    if [[ $choice == 1 ]]; then
        printf '\n在你自己电脑上执行 cat ~/.ssh/id_ed25519.pub，把输出的那一行复制过来。\n'
        printf '还没有密钥的话，先在自己电脑上执行 ssh-keygen -t ed25519。\n\n'
        while true; do
            ask value '粘贴公钥（回车返回）: ' && [[ -n $value ]] || return 0
            if fp=$(key_tool check "$value" 2>&1); then
                [[ $'\n'$list == *$'\t'"$fp"$'\t'* ]] || break
                printf '这把公钥已经在里面了。\n'; continue
            fi
            printf '%s\n' "$fp"
            # Swallow the rest of a pasted private key so it is not taken as further answers.
            if [[ $fp == *私钥* ]]; then while read -r -t 0.3 _; do :; done; fi
        done
        install -d -m 700 -o "$user" -g "$group" "$home/.ssh"
        if [[ -s $file && -n $(tail -c 1 "$file") ]]; then printf '\n' >> "$file"; fi
        printf '%s\n' "$value" >> "$file"
        chown "$user:$group" "$file"; chmod 600 "$file"
        printf '\n已添加。现在可以在你电脑上用这把密钥登录 %s。\n' "$user"
        port=${session_port:-$(ssh_ports | cut -d, -f1)}
        printf '    %s\n' "$(ssh_login_hint "${port:-22}" "$user")"
        # sshd ignores keys when the home directory is writable by others.
        if (( 8#$(stat -c %a "$home") & 8#022 )); then
            printf '注意：%s 的权限是 %s，SSH 会拒绝使用公钥；执行 chmod 755 %s 即可。\n' "$home" "$(stat -c %a "$home")" "$home"
        fi
        return 0
    fi
    while true; do
        ask number '要删除第几把？（回车返回）: ' && [[ -n $number ]] || return 0
        [[ ! $number =~ ^[0-9]+$ ]] || (( 10#$number < 1 || 10#$number > count )) || break
        printf '请输入 1 到 %s 之间的编号。\n' "$count"
    done
    number=$((10#$number))
    IFS=$'\t' read -r _ kind fp comment <<< "$(sed -n "${number}p" <<< "$list")"
    if [[ $user == "$auth_user" && $fp == "$auth_key" ]]; then
        printf '这是你当前窗口登录用的密钥，不能删除。\n'; return 0
    fi
    if [[ $pa == no ]] && (( count == 1 )); then
        printf 'SSH 已关闭密码登录，删掉最后这把公钥后 %s 就没法登录了，所以不能删。\n' "$user"; return 0
    fi
    confirm "确认删除第 $number 把（$kind $comment）？" || { printf '已取消。\n'; return 0; }
    key_tool remove "$file" "$number" || die '删除失败，公钥没有改动。'
    printf '已删除。用这把密钥的电脑以后就不能再登录 %s 了。\n' "$user"
}
password_login() {
    local want=$1 expected=no current content backup='' user with_keys=''
    [[ $want == off ]] || expected=yes
    ssh_preflight pending
    grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config ||
        die 'SSH 主配置没有引入 /etc/ssh/sshd_config.d，无法安全修改，SSH 配置未改动。'
    current=$(sshd_value passwordauthentication) || current=''
    if [[ $current == "$expected" ]]; then
        if [[ $want == off ]]; then printf 'SSH 密码登录本来就是关闭的。\n'; else printf 'SSH 密码登录本来就是允许的。\n'; fi
        return 0
    fi
    if [[ $want == off ]]; then
        # Never close password login unless someone can still get in with a key.
        if [[ -n ${client_addr:-} ]]; then
            session_auth
            [[ $auth_method == publickey ]] || die "当前窗口不是用密钥登录的（${auth_method:-查不到登录方式}）。请先在菜单 11 里添加公钥，用密钥登录一次，再在那个窗口里关闭密码登录。"
        else
            for user in $(login_users); do
                (( $(key_count "$user") == 0 )) || with_keys+="${with_keys:+、}$user"
            done
            [[ -n $with_keys ]] || die '服务器上没有任何用户配置了公钥，关闭密码登录后就没人能登录了。'
            printf '当前不是 SSH 连接。这些用户有公钥，关闭后只能用它们登录：%s\n' "$with_keys"
        fi
        printf '关闭后所有用户（包括 root）都只能用密钥登录，猜密码的攻击会全部失效；已经连着的窗口不受影响。\n'
        confirm '关闭 SSH 密码登录？' y || cancel
        content=$'# Managed by vpsfw: SSH password login is off.\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
    else
        printf '打开后用户可以用密码登录 SSH，root 是否能用密码仍按原来的设置。\n'
        confirm '打开 SSH 密码登录？' || cancel
        content=$'# Managed by vpsfw: SSH password login is on.\nPasswordAuthentication yes\n'
    fi
    [[ ! -e $AUTH_CONF ]] || backup=$(cat "$AUTH_CONF")
    # Files in sshd_config.d are read before the main config and the first value wins, so this one takes effect.
    printf '%s' "$content" > "$AUTH_CONF.tmp" && chmod 644 "$AUTH_CONF.tmp" && mv -f "$AUTH_CONF.tmp" "$AUTH_CONF"
    if ! sshd -t || ! systemctl reload ssh.service || [[ $(sshd_value passwordauthentication) != "$expected" ]]; then
        if [[ -n $backup ]]; then printf '%s\n' "$backup" > "$AUTH_CONF"; else rm -f "$AUTH_CONF"; fi
        sshd -t && systemctl reload ssh.service || true
        die '修改没有生效，已恢复原来的设置。'
    fi
    if [[ $want == off ]]; then printf 'SSH 密码登录已关闭，现在只能用密钥登录。\n'
    else printf 'SSH 密码登录已打开。\n'; fi
}
menu_auth() {
    local pa choice
    session_auth
    auth_status "${auth_user:-${SUDO_USER:-root}}"
    pa=$(sshd_value passwordauthentication) || pa=''
    printf '\n  1) 修改密码\n  2) 管理公钥\n'
    if [[ $pa == no ]]; then printf '  3) 打开密码登录\n\n'; else printf '  3) 关闭密码登录（只允许密钥登录）\n\n'; fi
    while true; do
        ask choice '请选择 [1-3]（回车返回）: ' && [[ -n $choice ]] || return 0
        case $choice in
            1) ask_login_user '修改哪个用户的密码？' || return 0; bash "$SELF" passwd "$REPLY" || true; return 0 ;;
            2) ask_login_user '管理哪个用户的公钥？' || return 0; bash "$SELF" keys "$REPLY" || true; return 0 ;;
            3)
                if [[ $pa == no ]]; then bash "$SELF" password-login on || true
                else bash "$SELF" password-login off || true; fi
                return 0 ;;
            *) printf '请输入 1、2 或 3。\n' ;;
        esac
    done
}
menu_unban() {
    local ip list
    list=" $(f2b_field 'Banned IP list') "
    while true; do
        printf '\n'
        ask ip '要解封哪个 IP？（回车跳过）: ' && [[ -n $ip ]] || return 0
        [[ $list != *" $ip "* ]] || break
        printf '%s 不在封禁名单里。\n' "$ip"
    done
    if fail2ban-client set sshd unbanip "$ip" >/dev/null; then printf '已解封 %s。\n' "$ip"
    else printf '解封失败，请查看 Fail2ban 状态。\n'; fi
}
ports_command() {
    local op=${1:-list} list=${2:-} proto source new='' p protocol comment covering
    command -v ufw >/dev/null || die '还没有初始化：请先在菜单选 1，或运行 vpsfw install。'
    load_rules
    if [[ $op == list ]]; then
        (( $# <= 1 )) || die 'ports list 无需其他参数。'
        list_ports; return
    fi
    case "$op" in
        add|delete)
            (( $# >= 2 && $# <= 4 )) || die '用法：ports add/delete 端口列表 [协议] [来源]'
            proto=${3:-tcp}; source=${4:-any} ;;
        change)
            (( $# >= 3 && $# <= 5 )) || die '用法：ports change 旧端口 新端口 [协议] [来源]'
            list=$(clean_ports "$list"); new=$(clean_ports "$3"); proto=${4:-tcp}; source=${5:-any}
            valid_spec "$list" && valid_spec "$new" || die '替换操作每次接受一个端口或范围。'
            [[ ${new%%:*} != "${new##*:}" ]] || new=${new%%:*}
            [[ ${list%%:*} != "${list##*:}" ]] || list=${list%%:*}
            [[ $list != "$new" ]] || die '新旧端口相同。' ;;
        *) die 'ports 支持 list、add、delete、change。' ;;
    esac
    proto=$(printf '%s' "$proto" | tr '[:upper:]' '[:lower:]')
    [[ $proto == tcp || $proto == udp || $proto == both ]] || die "协议只能是 tcp、udp 或 both（两者都要），收到：$proto"
    source=$(normalize_source "$source") || die '来源地址无效。'
    parse_ports "$list"
    local protocols=(tcp udp)
    [[ $proto == both ]] || protocols=("$proto")
    # Validate the entire batch before the first mutation.
    for p in "${ports[@]}"; do
        for protocol in "${protocols[@]}"; do
            check_ssh_collision "$p" "$protocol"
            if comment=$(rule_info "$p" "$protocol" "$source"); then
                [[ $comment != *SSH* && $comment != *ssh* ]] || die "$p/$protocol 是 SSH 入口，请用菜单 8「修改 SSH 端口」管理。"
            else
                local lookup_status=$?
                (( lookup_status == 1 )) || die '无法明确识别现有规则。'
                [[ $op == add ]] || die "找不到 $p/${protocol}（来源 $(source_label "$source")）的放行规则。用 vpsfw ports list 查看现有规则。"
            fi
            if [[ $op == change ]]; then
                check_ssh_collision "$new" "$protocol"
                if comment=$(rule_info "$new" "$protocol" "$source"); then
                    [[ $comment != *SSH* && $comment != *ssh* ]] || die "$new/$protocol 是 SSH 入口，不能作为替换目标。"
                else
                    local lookup_status=$?
                    (( lookup_status == 1 )) || die '无法明确识别新端口规则。'
                fi
            fi
        done
    done
    local joined
    joined=$(IFS=,; printf '%s' "${ports[*]}")
    case "$op" in
        add) printf '\n添加放行：%s' "$joined" ;;
        delete) printf '\n删除放行：%s' "$joined" ;;
        change) printf '\n替换放行：%s → %s' "$list" "$new" ;;
    esac
    printf '  %s  来源 %s\n' "$(proto_label "$proto")" "$(source_label "$source")"
    backup_ufw
    # Complete all additions before any deletions during a replacement.
    if [[ $op == change ]]; then
        for protocol in "${protocols[@]}"; do
            if ! existing_rule "$new" "$protocol" "$source"; then port_rule add "$new" "$protocol" "$source"; fi
            printf '  ✓ 已放行 %s/%s\n' "$new" "$protocol"
        done
    fi
    for p in "${ports[@]}"; do
        for protocol in "${protocols[@]}"; do
            case "$op" in
                add)
                    if existing_rule "$p" "$protocol" "$source"; then
                        printf '  · %s/%s 已经放行，跳过\n' "$p" "$protocol"
                    else
                        port_rule add "$p" "$protocol" "$source"
                        printf '  ✓ 已放行 %s/%s\n' "$p" "$protocol"
                    fi ;;
                delete|change)
                    port_rule delete "$p" "$protocol" "$source"
                    printf '  ✓ 已删除 %s/%s\n' "$p" "$protocol" ;;
            esac
        done
    done
    load_rules
    prune_backups
    # Point out rules that still decide access, instead of a generic disclaimer.
    for p in "${ports[@]}"; do
        for protocol in "${protocols[@]}"; do
            covering=''
            if [[ $op == add && $source != any ]]; then
                covering=$(covering_rules "$p" "$protocol" any)
                [[ -z $covering ]] || printf '\n注意：%s/%s 还有对所有来源开放的规则，只限来源 %s 不会生效：\n%s\n如需收紧，请删除上面这条规则。\n' "$p" "$protocol" "$source" "$covering"
            elif [[ $op != add ]]; then
                covering=$(covering_rules "$p" "$protocol")
                [[ -z $covering ]] || printf '\n注意：%s/%s 仍被下面的规则放行：\n%s\n' "$p" "$protocol" "$covering"
            fi
        done
    done
    if [[ $op != delete ]]; then
        local idle='' targets=("${ports[@]}")
        [[ $op != change ]] || targets=("$new")
        for p in "${targets[@]}"; do
            for protocol in "${protocols[@]}"; do
                [[ -n $(ss -H -ln"${protocol:0:1}" "sport >= :${p%%:*} and sport <= :${p##*:}" 2>/dev/null) ]] ||
                    idle+="${idle:+、}${p/:/-}/$protocol"
            done
        done
        [[ -z $idle ]] || printf '\n目前没有程序在监听 %s，服务启动后外部才能访问。\n' "$idle"
    fi
    if [[ $(ufw status) != 'Status: active'* ]]; then
        printf '\n防火墙当前未启用，规则已保存，启用后才生效（菜单 7）。\n'
    elif [[ $op != delete ]]; then
        printf '\n服务商安全组（云防火墙）也需要放行对应端口，外部才能访问。\n'
    fi
}
ufw_switch() {
    command -v ufw >/dev/null || die '还没有初始化：请先在菜单选 1，或运行 vpsfw install。'
    if [[ $1 == enable ]]; then
        local p current
        current=$(ssh_ports)
        [[ -n $current ]] || die '无法识别 SSH 端口，拒绝启用。'
        printf '启用防火墙：先确保 SSH 端口 %s 放行，其他未放行的入站连接将被拒绝。\n' "$current"
        confirm '现在启用？' y || cancel
        IFS=, read -r -a current_ports <<< "$current"
        for p in "${current_ports[@]}"; do allow_ssh "$p"; done
        if [[ -n ${session_port:-} ]]; then allow_ssh "$session_port"; fi
        ufw --force enable
    else
        printf '停用防火墙后，服务器上所有监听中的端口都会对外开放（Fail2ban 仍然工作）。\n'
        confirm '确认停用？' || cancel
        ufw disable
    fi
}
# Count terminal cells rather than characters: CJK characters take two cells,
# so Chinese labels and two-digit numbers stay aligned. ●, · and … take one.
menu_width() {
    local text=${1//[●·…]/.} ascii
    ascii=${text//[! -~]/}
    REPLY=$(( ${#ascii} + (${#text} - ${#ascii}) * 2 ))
}
# Print text padded to the given number of terminal cells.
pad() {
    menu_width "$1"
    local padding=$(( $2 - REPLY ))
    (( padding > 0 )) || padding=0
    printf '%s%*s' "$1" "$padding" ''
}
menu_pair() {
    local left=$1 right=$2 padding
    menu_width "$left"
    padding=$((28 - REPLY))
    (( padding >= 0 )) || padding=0
    printf '  %s%*s    %s\n' "$left" "$padding" '' "$right"
}
menu_item() {
    printf '  %s%2s.%s %s' "$cyan" "$1" "$reset" "$2"
}
menu_rule() {
    local line
    printf -v line '%*s' "$menu_span" ''
    printf '  %s%s%s\n' "$purple" "${line// /─}" "$reset"
}
menu_draw() {
    local fw=$1 ban=$2 current=$3 columns=$4
    local cyan='' purple='' reset='' bold='' dim=''
    if [[ -t 1 && ${TERM:-dumb} != dumb && ${NO_COLOR+x} != x ]]; then
        cyan=$'\033[36m'; purple=$'\033[34m'; reset=$'\033[0m'
        bold=$'\033[1m'; dim=$'\033[90m'
    fi
    local menu_span=60 wide=1 i left right padding
    if (( columns < 64 )); then
        wide=0; menu_span=$((columns - 4))
        (( menu_span >= 24 )) || menu_span=24
    fi
    printf '\n'
    if (( columns >= 44 )); then
        printf '%s' "$cyan"
        cat <<'LOGO'
  __     ______  ____  _______        __
  \ \   / /  _ \/ ___||  ___\ \      / /
   \ \ / /| |_) \___ \| |_   \ \ /\ / /
    \ V / |  __/ ___) |  _|   \ V  V /
     \_/  |_|   |____/|_|      \_/\_/
LOGO
        printf '%s' "$reset"
    fi
    printf '\n  %sVPS Firewall  ·  Debian 13%s\n' "$bold" "$reset"
    printf '  %s服务器端口与 SSH 管理%s\n\n' "$dim" "$reset"
    menu_rule
    if (( wide )); then
        menu_pair "UFW       $fw" "Fail2ban  $ban"
        menu_pair "SSH       $current" "当前连接  ${session_port:-控制台}"
    else
        printf '  UFW       %s\n  Fail2ban  %s\n  SSH       %s\n  当前连接  %s\n' "$fw" "$ban" "$current" "${session_port:-控制台}"
    fi
    menu_rule
    printf '\n'
    local labels=('初始化防护' '状态与规则' '添加放行端口' '删除放行端口' '替换放行端口' '查看端口监听'
                  '防火墙开关' '修改 SSH 端口' 'Fail2ban 管理' 'SSH 登录记录' 'SSH 登录方式' 'Ping 开关')
    if (( wide )); then
        menu_pair '端口管理' '防护与 SSH'
        printf '\n'
        for ((i=0;i<6;i++)); do
            left=${labels[i]}
            menu_item "$((i+1))" "$left"
            if (( i < 6 )); then
                menu_width "$left"; padding=$((28 - 4 - REPLY))
                # The first column already supplied the row indentation.
                printf '%*s    %s%2s.%s %s' "$padding" '' "$cyan" "$((i+7))" "$reset" "${labels[i+6]}"
            fi
            printf '\n\n'
        done
    else
        printf '  %s端口管理%s\n\n' "$dim" "$reset"
        for ((i=0;i<12;i++)); do
            if (( i == 6 )); then printf '\n  %s防护与 SSH%s\n\n' "$dim" "$reset"; fi
            menu_item "$((i+1))" "${labels[i]}"; printf '\n\n'
        done
    fi
    menu_rule
    menu_item 0 '退出'; printf '\n'; menu_rule
    if [[ -f $PENDING_FILE ]]; then
        printf '\n  %sSSH 迁移待确认%s\n  请从新端口登录，再选择 8 确认。\n' "$cyan" "$reset"
    elif [[ $fw == 未安装 ]]; then
        printf '\n  %s尚未初始化%s\n  新服务器请先选择 1。\n' "$cyan" "$reset"
    fi
    printf '\n'
}
# ── Menu dialogs: validate each answer on the spot; a blank answer goes back to the menu. ──
ask_ports() {
    local value
    while ask value "$1" && [[ -n $value ]]; do
        if REPLY=$(parse_ports "$value" && IFS=, && printf '%s' "${ports[*]}"); then return 0; fi
    done
    return 1
}
ask_proto() {
    local value
    while ask value '协议：1) TCP  2) UDP  3) TCP+UDP  [回车 = 1]: '; do
        case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
            ''|1|tcp) REPLY=tcp; return 0 ;;
            2|udp) REPLY=udp; return 0 ;;
            3|both|tcp+udp) REPLY=both; return 0 ;;
            *) printf '请输入 1、2 或 3。\n' ;;
        esac
    done
    return 1
}
ask_source() {
    local value
    while ask value '来源：只允许某个 IP 或网段时填写，回车 = 所有来源: '; do
        if REPLY=$(normalize_source "${value:-any}"); then return 0; fi
    done
    return 1
}
# Number the plain allow rules into menu_rules; SSH entries are left to the SSH menu.
show_rules() {
    local rp rproto rsource rcomment ssh p covers n=0
    menu_rules=()
    load_rules
    ssh=$(ssh_ports 2>/dev/null) || ssh=''
    while IFS=$'\t' read -r rp rproto rsource rcomment; do
        [[ $rcomment != *SSH* && $rcomment != *ssh* ]] || continue
        covers=0
        if [[ $rproto == tcp ]]; then
            for p in ${ssh//,/ } ${session_port:-}; do
                (( 10#$p < 10#${rp%%:*} || 10#$p > 10#${rp##*:} )) || covers=1
            done
        fi
        (( ! covers )) || continue
        menu_rules+=("$rp"$'\t'"$rproto"$'\t'"$rsource")
        if (( n == 0 )); then
            printf '\n  %s%s%s%s备注\n' "$(pad 编号 6)" "$(pad 端口 14)" "$(pad 协议 6)" "$(pad 来源 22)"
        fi
        n=$((n + 1))
        printf '  %s%s%s%s%s\n' "$(pad "$n" 6)" "$(pad "$rp" 14)" "$(pad "$(proto_label "$rproto")" 6)" \
            "$(pad "$(source_label "$rsource")" 22)" "$rcomment"
    done < <(rule_info --list)
    if (( n == 0 )); then
        printf '\n目前没有可管理的端口放行规则（SSH 入口请用菜单 8 管理）。\n'
        return 1
    fi
    printf '\n  SSH 入口不在此列出，请用菜单 8 管理。\n\n'
}
# Read rule numbers into picked; $2=1 allows several, e.g. "1,3" or "1 3".
ask_rule_numbers() {
    local value item seen
    while ask value "$1" && [[ -n $value ]]; do
        value=${value//，/ }; value=${value//,/ }
        picked=(); seen=' '
        for item in $value; do
            if [[ ! $item =~ ^[0-9]+$ ]] || (( 10#$item < 1 || 10#$item > ${#menu_rules[@]} )); then
                printf '没有编号 %s，请输入 1 到 %s 之间的编号。\n' "$item" "${#menu_rules[@]}"; picked=(); break
            fi
            [[ $seen == *" $((10#$item)) "* ]] || picked+=($((10#$item - 1)))
            seen+="$((10#$item)) "
        done
        (( ${#picked[@]} )) || continue
        if (( ${2:-0} == 0 && ${#picked[@]} > 1 )); then printf '一次只能选一条。\n'; continue; fi
        return 0
    done
    return 1
}
menu_add() {
    local list proto source
    printf '\n添加放行端口。多个端口用逗号分隔，范围写 8000-8010。\n\n'
    ask_ports '端口（回车返回）: ' || return 0; list=$REPLY
    ask_proto || return 0; proto=$REPLY
    ask_source || return 0; source=$REPLY
    printf '\n将放行：%s  %s  来源 %s\n' "$list" "$(proto_label "$proto")" "$(source_label "$source")"
    confirm '确认添加？' y || { printf '已取消。\n'; return 0; }
    bash "$SELF" ports add "$list" "$proto" "$source" || true
}
menu_delete() {
    local i key rp rproto rsource list groups=()
    show_rules || return 0
    ask_rule_numbers '要删除哪几条？输入编号，多个用逗号分隔（回车返回）: ' 1 || return 0
    printf '\n将删除：\n'
    for i in "${picked[@]}"; do
        IFS=$'\t' read -r rp rproto rsource <<< "${menu_rules[i]}"
        printf '  %s/%s  来源 %s\n' "$rp" "$rproto" "$(source_label "$rsource")"
        key="$rproto"$'\t'"$rsource"
        [[ " ${groups[*]-} " == *" $key "* ]] || groups+=("$key")
    done
    confirm '确认删除？' || { printf '已取消。\n'; return 0; }
    # One call per protocol and source; each call checks its whole batch before changing anything.
    for key in "${groups[@]}"; do
        list=''
        for i in "${picked[@]}"; do
            IFS=$'\t' read -r rp rproto rsource <<< "${menu_rules[i]}"
            [[ "$rproto"$'\t'"$rsource" != "$key" ]] || list+=${list:+,}$rp
        done
        bash "$SELF" ports delete "$list" "${key%%$'\t'*}" "${key#*$'\t'}" || true
    done
}
menu_change() {
    local rp rproto rsource value new
    show_rules || return 0
    ask_rule_numbers '要替换哪一条？输入编号（回车返回）: ' 0 || return 0
    IFS=$'\t' read -r rp rproto rsource <<< "${menu_rules[picked[0]]}"
    printf '\n原规则：%s/%s  来源 %s\n' "$rp" "$rproto" "$(source_label "$rsource")"
    while true; do
        ask value '新端口或范围（回车返回）: ' && [[ -n $value ]] || return 0
        new=$(clean_ports "$value")
        valid_spec "$new" && [[ $new != "$rp" ]] && break
        printf '请输入一个与原来不同的端口（1-65535）或范围，例如 8443 或 8000-8010。\n'
    done
    printf '\n将替换：%s → %s  %s  来源 %s（先放行新端口，再删除旧规则）\n' "$rp" "$new" "$(proto_label "$rproto")" "$(source_label "$rsource")"
    confirm '确认替换？' y || { printf '已取消。\n'; return 0; }
    bash "$SELF" ports change "$rp" "$new" "$rproto" "$rsource" || true
}
# Whether outside traffic can reach a listening port: sets REPLY and state_color.
firewall_state() {
    local proto=$1 port=$2 addr=$3 rp rproto rsource item partial=0
    case $addr in 127.*|'[::1]'|::1) REPLY='仅本机访问'; state_color=$c_dim; return 0 ;; esac
    if (( ! fw_active )); then REPLY='防火墙未启用'; state_color=$c_warn; return 0; fi
    while IFS=$'\t' read -r rp rproto rsource; do
        [[ -n $rp && ( $rproto == "$proto" || $rproto == any ) ]] || continue
        for item in ${rp//,/ }; do
            (( 10#$port >= 10#${item%%:*} && 10#$port <= 10#${item##*:} )) || continue
            if [[ $rsource == any ]]; then REPLY='● 已放行'; state_color=$c_ok; return 0; fi
            partial=1
        done
    done <<< "$cover_rules"
    if (( partial )); then REPLY='● 仅部分来源'; state_color=$c_warn
    else REPLY='● 未放行'; state_color=$c_err; fi
}
show_listeners() {
    set_colors
    local fw_active=0 cover_rules='' listeners proto port addr prog state_color idle='' rp rproto rsource item label found
    if command -v ufw >/dev/null; then
        [[ $(ufw status 2>/dev/null) != 'Status: active'* ]] || fw_active=1
        load_rules
        cover_rules=$(rule_info --cover) || cover_rules=''
    fi
    listeners=$(ss -H -lntup | awk '{
        port=$5; sub(/.*:/, "", port); addr=$5; sub(/:[^:]*$/, "", addr)
        prog="-"; if (match($0, /users:\(\("[^"]+"/)) prog=substr($0, RSTART+9, RLENGTH-10)
        if (!seen[$1 " " port " " prog]++) printf "%s\t%s\t%s\t%s\n", $1, port, addr, prog
    }' | sort -t$'\t' -k2,2n -k1,1) || listeners=''
    printf '\n  %s%s%s%s%s防火墙%s\n' "$c_dim" "$(pad 协议 6)" "$(pad 端口 8)" "$(pad 监听地址 24)" "$(pad 程序 18)" "$c_off"
    while IFS=$'\t' read -r proto port addr prog; do
        [[ -n $port ]] || continue
        firewall_state "$proto" "$port" "$addr"
        printf '  %s%s%s%s%s%s%s\n' "$(pad "$proto" 6)" "$(pad "$port" 8)" "$(pad "$addr" 24)" "$(pad "$prog" 18)" \
            "$state_color" "$REPLY" "$c_off"
    done <<< "$listeners"
    # Allowed ports nothing is listening on yet, from the same rules as the column above.
    while IFS=$'\t' read -r rp rproto rsource; do
        [[ -n $rp ]] || continue
        for item in ${rp//,/ }; do
            found=0
            while IFS=$'\t' read -r proto port addr prog; do
                if [[ -n $port && ( $proto == "$rproto" || $rproto == any ) ]] &&
                   (( 10#$port >= 10#${item%%:*} && 10#$port <= 10#${item##*:} )); then
                    found=1; break
                fi
            done <<< "$listeners"
            label=${item/:/-}; [[ $rproto == any ]] || label+="/$rproto"
            (( found )) || [[ "、$idle、" == *"、$label、"* ]] || idle+="${idle:+、}$label"
        done
    done <<< "$cover_rules"
    [[ -z $idle ]] || printf '\n  %s已放行但目前没有程序监听：%s%s\n' "$c_dim" "$idle" "$c_off"
    printf '\n'
}
menu_firewall() {
    command -v ufw >/dev/null || { printf '还没有初始化，请先选择 1。\n'; return 0; }
    if [[ $(ufw status) == 'Status: active'* ]]; then
        printf '\n防火墙当前：已启用\n'
        bash "$SELF" firewall disable || true
    else
        printf '\n防火墙当前：未启用\n'
        bash "$SELF" firewall enable || true
    fi
}
menu_ssh_change() {
    local new current choice old_ports new_port
    if [[ -f $PENDING_FILE ]]; then
        { read -r _; read -r old_ports; read -r new_port; } < "$PENDING_FILE" || true
        printf '\nSSH 端口迁移进行中：%s → %s\n\n' "$old_ports" "$new_port"
        printf '  1) 确认迁移：关闭旧端口（要在用新端口 %s 登录的窗口里操作）\n' "$new_port"
        printf '  2) 回退迁移：恢复成旧端口 %s\n\n' "$old_ports"
        while true; do
            ask choice '请选择 [1-2]（回车返回）: ' && [[ -n $choice ]] || return 0
            case $choice in
                1) bash "$SELF" ssh finish || true; return 0 ;;
                2) bash "$SELF" ssh rollback || true; return 0 ;;
                *) printf '请输入 1 或 2。\n' ;;
            esac
        done
    fi
    current=$(ssh_ports 2>/dev/null) || current='未知'
    printf '\n当前 SSH 端口：%s\n建议使用 10000-65535 之间、没被其他程序占用的端口。\n\n' "${current:-未知}"
    while true; do
        ask new '新的 SSH 端口（回车返回）: ' && [[ -n $new ]] || return 0
        valid_port "$new" && break
        printf '请输入 1 到 65535 之间的整数。\n'
    done
    bash "$SELF" ssh change "$new" || true
}
menu() {
    local choice reply source columns
    while true; do
        if [[ -t 1 && ${TERM:-dumb} != dumb ]]; then printf '\033[2J\033[H'; fi
        local fw='未安装' ban='未安装' current='未知' raw
        if command -v ufw >/dev/null; then
            raw=$(ufw status 2>/dev/null) || raw=''
            case "$raw" in
                'Status: active'*) fw='已启用' ;;
                'Status: inactive'*) fw='未启用' ;;
                *) fw='状态异常' ;;
            esac
        fi
        if command -v fail2ban-client >/dev/null; then
            if fail2ban-client status sshd >/dev/null 2>&1; then ban='保护中'; else ban='未就绪'; fi
        fi
        current=$(ssh_ports 2>/dev/null) || current='未知'
        [[ -n $current ]] || current='未知'
        if (( ${#current} > 18 )); then current="${current:0:15}..."; fi
        columns=$(tput cols 2>/dev/null) || columns=${COLUMNS:-80}
        [[ $columns =~ ^[0-9]+$ ]] || columns=80
        menu_draw "$fw" "$ban" "$current" "$columns"
        while true; do
            ask choice '  请选择 [0-12]: ' || return 0
            case "$choice" in
                0|q|Q) return 0 ;;
                [1-9]|1[0-2]) break ;;
                '') ;;
                *) printf '  没有这个选项，请输入 0 到 12。\n' ;;
            esac
        done
        case "$choice" in
            1) bash "$SELF" install || true ;;
            2) bash "$SELF" status || true ;;
            3) menu_add ;;
            4) menu_delete ;;
            5) menu_change ;;
            6) show_listeners || true ;;
            7) menu_firewall ;;
            8) menu_ssh_change ;;
            9)
                show_f2b
                [[ -z $f2b_status || -z $(f2b_field 'Banned IP list') ]] || menu_unban
                if (( f2b_sync )); then
                    printf '\n'
                    if confirm '按当前 SSH 端口重新同步 Fail2ban？' y; then bash "$SELF" sync || true; fi
                fi ;;
            10) menu_logins ;;
            11) menu_auth ;;
            12) menu_ping ;;
        esac
        ask reply $'\n按回车返回菜单……' || return 0
    done
}

# Runtime entry point.
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
ssh_port=''
mode=install
dispatch_args=()
if (( $# == 0 )); then mode=menu; fi
case "${1:-}" in
    install) shift ;;
    help) usage; exit 0 ;;
    status|ssh|ports|firewall|sync|logins|passwd|keys|password-login|ping)
        mode=$1; shift; dispatch_args=("$@"); set -- ;;
esac
while (( $# )); do
    case "$1" in
        --ssh-port)
            (( $# >= 2 )) || die '--ssh-port 缺少端口值。'
            ssh_port=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "未知参数：$1（使用 --help 查看帮助）" ;;
    esac
done
trap 'printf "\n操作中断：上面这一步执行失败（脚本第 %s 行），部分配置可能已经修改。\n请保留当前 SSH 连接，用菜单 2 查看状态后再重试。\n" "$LINENO" >&2' ERR
[[ $EUID -eq 0 ]] || die '需要 root 权限，请用 sudo vpsfw 运行。'
if [[ $mode =~ ^(install|menu|ssh|firewall|passwd|keys|password-login|ping)$ ]]; then
    [[ -t 0 ]] || die '请下载脚本后在交互终端运行，不要通过管道运行。'
fi
. /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] || die '此脚本针对 Debian 13。'
[[ -d /run/systemd/system ]] || die '需要使用 systemd 的系统。'

session_port='' server_addr='' client_addr='' client_port=''
connection=$(ssh_connection)
if [[ -n $connection ]]; then
    read -r client_addr client_port server_addr session_port <<< "$connection"
    valid_port "$session_port" || die '无法正确解析当前 SSH 端口。'
fi
if [[ $mode != menu && $mode != status && $mode != logins ]]; then
    # Serialize writes across separate SSH windows.
    exec 9>/run/lock/vps-security.lock
    flock -n 9 || die '另一个管理操作正在运行，请稍后重试。'
fi
case "$mode" in
    menu) menu; exit 0 ;;
    status) show_status; exit 0 ;;
    logins)
        days=${dispatch_args[0]:-1}
        [[ ${#dispatch_args[@]} -le 1 && $days =~ ^[0-9]+$ ]] && (( 10#$days >= 1 && 10#$days <= 90 )) || die '用法：logins [天数，1 到 90]'
        show_logins "$((10#$days))"; exit 0 ;;
    ports) ports_command "${dispatch_args[@]}"; exit 0 ;;
    passwd|keys)
        (( ${#dispatch_args[@]} <= 1 )) || die "用法：$mode [用户]"
        session_auth
        if [[ $mode == passwd ]]; then change_password "${dispatch_args[0]:-${auth_user:-${SUDO_USER:-root}}}"
        else manage_keys "${dispatch_args[0]:-${auth_user:-${SUDO_USER:-root}}}"; fi
        exit 0 ;;
    ping)
        [[ ${#dispatch_args[@]} == 1 && ( ${dispatch_args[0]} == on || ${dispatch_args[0]} == off ) ]] || die '用法：ping off|on'
        ping_switch "${dispatch_args[0]}"; exit 0 ;;
    password-login)
        [[ ${#dispatch_args[@]} == 1 && ( ${dispatch_args[0]} == on || ${dispatch_args[0]} == off ) ]] || die '用法：password-login on|off'
        password_login "${dispatch_args[0]}"; exit 0 ;;
    firewall)
        [[ ${#dispatch_args[@]} == 1 && ( ${dispatch_args[0]} == enable || ${dispatch_args[0]} == disable ) ]] || die '用法：firewall enable|disable'
        ufw_switch "${dispatch_args[0]}"; exit 0 ;;
    ssh)
        case "${dispatch_args[0]:-}" in
            change)
                (( ${#dispatch_args[@]} == 2 )) || die '用法：ssh change 新端口'
                ssh_change "${dispatch_args[1]}" ;;
            finish|rollback)
                (( ${#dispatch_args[@]} == 1 )) || die 'finish 和 rollback 不需要额外参数。'
                if [[ ${dispatch_args[0]} == finish ]]; then ssh_finish; else ssh_rollback; fi ;;
            *) die '用法：ssh change 新端口 | ssh finish | ssh rollback' ;;
        esac
        exit 0 ;;
    sync)
        ssh_preflight pending
        ssh_snapshot
        start_transaction
        current=$(ssh_ports)
        write_f2b "$current"
        systemctl enable --quiet fail2ban
        systemctl restart fail2ban
        wait_f2b
        effective=$(fail2ban-client get sshd action nftables-multiport port)
        [[ $effective == "$current" ]] || die '其他配置覆盖了 Fail2ban 端口，已中止。'
        end_transaction
        prune_backups
        printf 'Fail2ban 已同步 SSH 端口：%s\n' "$current"
        exit 0 ;;
esac
[[ ! -e $PENDING_FILE ]] || die '有待确认的 SSH 迁移，请先完成或回退，暂不重新初始化。'
if [[ -n $session_port ]]; then
    [[ -z $ssh_port || $ssh_port == "$session_port" ]] || die "当前 SSH 连接使用 ${session_port}，--ssh-port 应填这个端口；修改 SSH 端口请用 vpsfw ssh change。"
    ssh_port=$session_port
elif [[ -z $ssh_port ]]; then
    printf '当前不是通过 SSH 连接（例如服务商网页控制台），需要手动填写 SSH 端口。\n'
    while true; do
        ask ssh_port '服务器 SSH 端口（默认 22）: ' || cancel
        ssh_port=${ssh_port:-22}
        valid_port "$ssh_port" && break
        printf '请输入 1 到 65535 之间的整数。\n'
    done
fi
valid_port "$ssh_port" || die 'SSH 端口必须是 1 到 65535 的整数。'
reinit=0
if command -v ufw >/dev/null && [[ $(ufw status 2>/dev/null) == 'Status: active'* ]] &&
   command -v fail2ban-client >/dev/null && fail2ban-client status sshd >/dev/null 2>&1; then
    reinit=1
    printf '\n这台服务器已经初始化过：防火墙已启用，Fail2ban 正在保护 SSH，通常不需要再做。\n'
    printf '重新初始化会重装软件包、覆盖 Fail2ban 的 SSH 设置（会先备份）并重设防火墙默认规则；已有的放行规则保留。\n'
fi
printf '\n初始化将会：\n'
printf '  · 安装 UFW 和 Fail2ban\n'
printf '  · 放行 SSH 端口 %s/TCP，拒绝其他未放行的入站连接（IPv4 和 IPv6），出站不限\n' "$ssh_port"
printf '  · SSH 登录 5 分钟内失败 5 次，封禁该 IP 10 分钟\n'
printf '  · 保留已有的 UFW 规则；备份后覆盖 /etc/fail2ban/jail.d/sshd.local\n'
printf '\n不修改 SSH 端口；其他端口初始化后用菜单 3 添加。\n'
printf '不适合 Docker 端口映射、NAT 转发、VPN 网关或已有复杂防火墙的服务器。\n'
printf '建议先打开服务商网页控制台备用，万一连不上可以从那里恢复。\n\n'
if (( reinit )); then confirm '仍要重新初始化？' || cancel '没有修改任何配置'
else confirm '开始初始化？' || cancel '没有修改任何配置'; fi

apt-get update
apt-get install -y ufw fail2ban python3 python3-systemd nftables iproute2 util-linux
load_rules

# Ensure the chosen SSH port actually has a TCP listener before changing UFW.
if ! ss -H -lnt "sport = :$ssh_port" | grep -q .; then
    die "未发现 TCP $ssh_port 正在监听，尚未修改 UFW 规则。"
fi

backup_dir=$(mktemp -d /var/backups/vps-security.XXXXXXXX)
cp -a /etc/ufw "$backup_dir/ufw"
cp -a /etc/default/ufw "$backup_dir/ufw-default"
cp -a /etc/fail2ban "$backup_dir/fail2ban"
printf '\n原配置备份：%s\n' "$backup_dir"
mkdir -p /etc/fail2ban/jail.d
jail_file=/etc/fail2ban/jail.d/sshd.local
had_jail=0
[[ ! -e $jail_file ]] || had_jail=1
restore_jail() {
    if (( had_jail )); then
        cp -a "$backup_dir/fail2ban/jail.d/sshd.local" "$jail_file"
    else
        rm -f "$jail_file"
    fi
}
all_ssh_ports=$(ssh_ports)
[[ -n $all_ssh_ports ]] || die '无法读取 SSH 配置端口。'
if ! write_f2b "$all_ssh_ports"; then
    restore_jail
    die "Fail2ban 配置检查失败，已恢复原 sshd.local。备份：$backup_dir"
fi

# Allow SSH first, including on already-active firewalls. Do not reset rules.
allow_ssh "$ssh_port"
IFS=, read -r -a all_ssh_array <<< "$all_ssh_ports"
for p in "${all_ssh_array[@]}"; do allow_ssh "$p"; done
if grep -q '^IPV6=' /etc/default/ufw; then
    sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
else
    printf '\nIPV6=yes\n' >> /etc/default/ufw
fi
# Add again after enabling IPv6 so both address families have the SSH rule.
allow_ssh "$ssh_port"
for p in "${all_ssh_array[@]}"; do allow_ssh "$p"; done
ufw default deny incoming
ufw default allow outgoing
ufw logging low
ufw --force enable
ufw reload

systemctl enable --quiet fail2ban
if ! systemctl restart fail2ban; then
    journalctl -u fail2ban -n 50 --no-pager || true
    die "Fail2ban 重启失败。UFW 已启用；原配置备份在 $backup_dir"
fi
# Wait for the jail, not merely systemctl's asynchronous start result.
ready=0
for ((attempt=0; attempt<30; attempt++)); do
    if fail2ban-client status sshd >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if (( ! ready )); then
    journalctl -u fail2ban -n 50 --no-pager || true
    die "30 秒内 SSH 防护未就绪。UFW 已启用；原配置备份在 $backup_dir"
fi

printf '\n── 防火墙规则 ──\n'
ufw status
prune_backups
printf '\n初始化完成：防火墙已启用，Fail2ban 正在保护 SSH 端口 %s。\n\n' "$all_ssh_ports"
printf '接下来：\n'
printf '  1. 不要关闭当前窗口，新开一个终端确认还能登录：%s\n' "$(ssh_login_hint "$ssh_port")"
printf '  2. 网站、数据库等其他端口，用菜单 3 添加放行（服务商安全组也要放行）\n\n'
printf '万一连不上：在当前窗口或服务商控制台执行 ufw disable 关闭防火墙；\n'
printf '如果是自己的 IP 被误封：fail2ban-client set sshd unbanip 你的公网IP\n'
