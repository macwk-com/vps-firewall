#!/usr/bin/env bash
# VPS Firewall — Debian 10–14, Ubuntu 18.04–26.04, Rocky and AlmaLinux 8–10; directly installed services.
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
VPS Firewall — Linux 服务器安全与端口管理
用法：
  vpsfw                              # 彩色菜单
  vpsfw install                      # 初始化 UFW + Fail2ban
  vpsfw --ssh-port 34968              # 使用现有 SSH 端口初始化
  vpsfw ports list                   # 每个端口谁能访问
  vpsfw ports set 443,8000-8010 tcp any       # 放行端口，所有 IP 都能访问
  vpsfw ports set 5432 tcp 192.0.2.8,198.51.100.0/24
                                     # 只允许这些 IP 访问（白名单）
  vpsfw ports add 5432 tcp 203.0.113.9        # 往白名单里再加一个 IP
  vpsfw ports delete 5432 tcp 203.0.113.9     # 从白名单里去掉一个 IP
  vpsfw ports change 443 8443 tcp    # 换端口号，谁能访问保持不变
  vpsfw ports close 5432 tcp         # 关闭端口（删掉它的全部放行规则）
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

ports set 端口列表 协议 来源列表|any：来源用逗号分隔，any 表示所有 IP。
ports add/delete 端口列表 [协议] [来源]：加一条或删一条来源，来源默认 any。
协议是 tcp、udp 或 both（两者都要），默认 tcp；范围写 8000:8010 或 8000-8010。
SSH 端口可以用 ports set 限制来源（必须包含当前连接的 IP）；换 SSH 端口用 ssh change。
初始化仅放行 SSH，其他端口通过端口访问管理放行。保留已有 UFW 规则。
适用 Debian 10–14、Ubuntu 18.04–26.04、Rocky / AlmaLinux 8–10 宿主机入站流量；不管理应用、容器映射和路由转发。
SSH 迁移支持系统自带的 SSH 服务（含 Ubuntu 的 socket 模式），保留新旧入口直到新会话确认。
HELP
}
# Systems whose ssh, ufw, fail2ban and Python versions this script has been checked against.
supported_os() {
    case ${ID:-} in
        debian) [[ ${VERSION_ID:-} =~ ^(10|11|12|13|14)$ || ${VERSION_CODENAME:-} == forky ]] ;;
        ubuntu) [[ ${VERSION_ID:-} =~ ^(18|20|22|24|26)\.04$ ]] ;;
        rocky|almalinux) [[ ${VERSION_ID%%.*} =~ ^(8|9|10)$ ]] ;;
        *) return 1 ;;
    esac
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
# `rule_info --access SSH端口列表` groups them per port as port<TAB>proto<TAB>sources<TAB>is-SSH, proto
# "both" when TCP and UDP let in the same comma-separated sources;
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
if sys.argv[1]=="--access":
    ssh=set(sys.argv[2].split(","))
    groups={}
    for row in rows:
        if listable(row): groups.setdefault(row[:2],set()).add(row[2])
    def order(s):
        if s=="any": return (0,0,0,0)
        n=ipaddress.ip_network(s)
        return (1,n.version,int(n.network_address),n.prefixlen)
    entries=[[rp,rproto,",".join(sorted(srcs,key=order)),int(rproto=="tcp" and rp in ssh)]
             for (rp,rproto),srcs in groups.items()]
    # One line per port when TCP and UDP let in the same sources.
    merged=[]
    for e in entries:
        twin=[o for o in entries if o[0]==e[0] and o[1]!=e[1] and o[2]==e[2] and not o[3] and not e[3]]
        if not twin: merged.append(e)
        elif e[1]=="tcp": merged.append([e[0],"both",e[2],0])
    merged.sort(key=lambda e:(int(e[0].split(":")[0]),int(e[0].split(":")[-1]),("tcp","udp","both").index(e[1])))
    for e in merged: print("\t".join(map(str,e)))
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
source_label() { if [[ $1 == any ]]; then printf '所有 IP'; else printf '%s' "$1"; fi; }
# Sources let in on one exact port and protocol, one per line: "any" or an address.
port_sources() {
    rule_info --list | awk -F'\t' -v p="$1" -v proto="$2" '$1 == p && $2 == proto {print $3}' | sort -u
}
# REPLY becomes "所有 IP" or the allowed addresses, shortened to about $2 terminal cells.
access_label() {
    local sources=$1 width=${2:-40} items text
    if [[ ,$sources, == *,any,* ]]; then REPLY='所有 IP'; return 0; fi
    IFS=, read -r -a items <<< "$sources"
    text="只允许 ${sources//,/、}"
    menu_width "$text"
    (( REPLY <= width )) || text="只允许 ${#items[@]} 个 IP：${items[0]} 等"
    REPLY=$text
}
# Sources separated by commas or spaces, normalised and comma-joined; "any" has to stand alone.
normalize_sources() {
    local value=${1//，/,} item out='' items=()
    read -r -a items <<< "${value//,/ }"
    for item in ${items[@]+"${items[@]}"}; do
        item=$(normalize_source "$item") || return 1
        [[ ,$out, == *,"$item",* ]] || out+=${out:+,}$item
    done
    [[ -n $out ]] || { printf '没有填写来源\n' >&2; return 1; }
    [[ $out == any || ,$out, != *,any,* ]] || { printf 'any（所有 IP）不能和具体的 IP 写在一起\n' >&2; return 1; }
    printf '%s' "$out"
}
# Refuse a source list for SSH port $1 that leaves out the address of this SSH session.
check_session_allowed() {
    [[ -n ${client_addr:-} && $1 == "${session_port:-}" ]] || return 0
    python3 - "$client_addr" "$2" <<'PY' || die "你现在是从 $client_addr 连上来的，它不在名单里：当前窗口不会断，但以后就登录不上了。名单里要有这个 IP。"
import ipaddress, sys
a = ipaddress.ip_address(sys.argv[1].split('%')[0])
if a.version == 6 and a.ipv4_mapped: a = a.ipv4_mapped
sys.exit(not any(s == 'any' or a in ipaddress.ip_network(s) for s in sys.argv[2].split(',') if s))
PY
}
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
            [[ $spec == *:* ]] || die "$spec 是 SSH 端口，换端口请到「SSH 管理 → 修改 SSH 端口」，限制来源用 ports set。"
            die "端口范围 ${spec/:/-} 包含 SSH 端口 ${p}，请拆开填写，SSH 端口在「SSH 管理」里改。"
        fi
    done
    listeners=$(ss -H -lntp "sport >= :$first and sport <= :$last") || die '无法检查实际监听端口。'
    [[ $listeners != *'"sshd"'* && $listeners != *'"sshd-session"'* ]] || die "端口 ${spec/:/-} 正由 SSH 使用，请到「SSH 管理」里改。"
}
# port_rule add|delete 端口 协议 来源 [备注]; the comment defaults to "VPS TCP" or "VPS UDP".
port_rule() {
    local op=$1 port=$2 proto=$3 source=$4 comment=${5:-}
    local args=()
    [[ $op != delete ]] || args+=(--force delete)
    args+=(allow)
    if [[ $source == any ]]; then args+=("$port/$proto")
    else args+=(from "$source" to any port "$port" proto "$proto"); fi
    if [[ $op != delete ]]; then
        [[ -n $comment ]] || comment="VPS ${proto^^}"
        args+=(comment "$comment")
    fi
    # SSH rules go first so no later deny rule can shadow them. `ufw insert 1` fails on an empty rule
    # set (fresh server) and for an IPv6 rule ahead of IPv4 ones, so fall back to a plain allow.
    if [[ $comment == SSH ]] && ufw insert 1 "${args[@]}" >/dev/null 2>&1; then return 0; fi
    ufw "${args[@]}" >/dev/null
}
# Open an SSH port to all IPs, unless it is limited to a whitelist.
allow_ssh() {
    local sources
    load_rules
    sources=$(port_sources "$1" tcp)
    [[ -z $sources || $'\n'$sources$'\n' == *$'\n'any$'\n'* ]] || return 0
    port_rule add "$1" tcp any SSH
}
# Sources of the SSH-labelled rules of a port.
ssh_rule_sources() {
    load_rules
    rule_info --list | awk -F'\t' -v p="$1" '$1 == p && $2 == "tcp" && $4 == "SSH" {print $3}'
}
delete_ssh_rules() {
    local source
    for source in $(ssh_rule_sources "$1"); do port_rule delete "$1" tcp "$source" || return 1; done
}
# The whitelist shared by SSH ports $1 (comma list), or nothing when any of them is open to all IPs.
ssh_whitelist() {
    local p sources all=''
    load_rules
    for p in ${1//,/ }; do
        sources=$(port_sources "$p" tcp)
        [[ -n $sources && $'\n'$sources$'\n' != *$'\n'any$'\n'* ]] || return 0
        all+=$sources$'\n'
    done
    printf '%s' "$all" | sort -u | paste -sd, -
}
# Add, then delete, the rules that make spec/protocol let in exactly the sources in $3
# (comma list, empty for none). Rules added here carry comment $4.
sync_sources() {
    local spec=$1 protocol=$2 target=$3 comment=${4:-} current source
    load_rules
    current=$(port_sources "$spec" "$protocol")
    for source in ${target//,/ }; do
        [[ $'\n'$current$'\n' != *$'\n'"$source"$'\n'* ]] || continue
        port_rule add "$spec" "$protocol" "$source" "$comment"
        printf '  ✓ %s/%s  允许 %s\n' "${spec/:/-}" "$protocol" "$(source_label "$source")"
    done
    for source in $current; do
        [[ ,$target, != *,"$source",* ]] || continue
        port_rule delete "$spec" "$protocol" "$source"
        printf '  ✓ %s/%s  移除 %s\n' "${spec/:/-}" "$protocol" "$(source_label "$source")"
    done
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
# Debian and Ubuntu call the service ssh, RHEL-family systems sshd; set for real in the entry point.
SSH_UNIT=ssh.service SSH_SOCKET_UNIT=ssh.socket
# Ubuntu 22.10+ lets systemd own the SSH sockets (Accept=no) and builds them from sshd_config.
ssh_socket_mode() {
    systemctl is-enabled --quiet "$SSH_SOCKET_UNIT" 2>/dev/null || systemctl is-active --quiet "$SSH_SOCKET_UNIT"
}
# Make sshd use a changed configuration; open connections stay up either way.
# In socket mode the service requires the socket, so restarting the socket also stops sshd, and the
# next connection starts it with the new settings. Restarting sshd on top of that races the
# activation and trips systemd's start limit, which takes the socket down with it.
ssh_reload() {
    if ssh_socket_mode; then
        systemctl reset-failed "$SSH_UNIT" "$SSH_SOCKET_UNIT" 2>/dev/null || true
        systemctl daemon-reload && systemctl restart "$SSH_SOCKET_UNIT" && systemctl is-active --quiet "$SSH_SOCKET_UNIT"
    else
        systemctl reload "$SSH_UNIT"
    fi
}
# SELinux only lets sshd bind ports labelled ssh_port_t (Rocky, AlmaLinux).
selinux_allow_ports() {
    command -v selinuxenabled >/dev/null && selinuxenabled || return 0
    command -v semanage >/dev/null || die 'SELinux 已启用，但缺少 semanage（policycoreutils-python-utils），无法给新 SSH 端口登记。'
    local p labelled
    labelled=$(semanage port -l | awk '$1 == "ssh_port_t" && $2 == "tcp" {for (i = 3; i <= NF; i++) print $i}' | tr -d ,)
    for p in ${1//,/ }; do
        [[ $'\n'$labelled$'\n' != *$'\n'"$p"$'\n'* ]] || continue
        semanage port -a -t ssh_port_t -p tcp "$p" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$p"
    done
}
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
# aggressive also counts attempts that end before authentication, such as trying keys against a real
# account after password login is off; normal mode never bans those. Plain TCP probes barely count.
F2B_FILTER='sshd[mode=aggressive]'
write_f2b() {
    local target_ports=$1
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/sshd.local <<EOF || return 1
[sshd]
enabled = true
filter = $F2B_FILTER
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
# Restrict automated rewrites to the includes distributions ship. Snapshot exactly the files edited.
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
        # RHEL-family systems pull in the system crypto policy, which only sets algorithms.
        if key == 'include' and not (p == main and words[1:] == ['/etc/ssh/sshd_config.d/*.conf']) \
                and words[1:] != ['/etc/crypto-policies/back-ends/opensshserver.config']:
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
    if ssh_socket_mode; then
        [[ $(systemctl show -p Accept --value "$SSH_SOCKET_UNIT") == no ]] ||
            die "$SSH_SOCKET_UNIT 是每个连接单独启动 sshd 的模式，脚本不会自动修改，SSH 配置未改动。"
    else
        systemctl is-active --quiet "$SSH_UNIT" || die "$SSH_UNIT 没有运行。"
    fi
    sshd -t
    local start
    start=$(systemctl cat "$SSH_UNIT" | awk '/^ExecStart=./ {line=$0} END {print line}')
    case $start in
        'ExecStart=/usr/sbin/sshd -D' | 'ExecStart=/usr/sbin/sshd -D $SSHD_OPTS' | 'ExecStart=/usr/sbin/sshd -D $OPTIONS' | \
        'ExecStart=/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY') ;;
        *) die 'SSH 使用自定义启动命令，无法安全自动修改。' ;;
    esac
    # Extra start options may carry crypto settings, but must not pick ports, addresses or a config file.
    python3 - "$(systemctl show "$SSH_UNIT" -p Environment --value)" <<'PY'
import pathlib, re, shlex, sys
def risky(value):
    words = shlex.split(value)
    for i, word in enumerate(words):
        if word.startswith(('-p', '-f')): return True
        if word.startswith('-o'):
            option = word[2:] or (words[i + 1] if i + 1 < len(words) else '')
            if re.split(r'[=\s]', option.strip())[0].lower() in ('port', 'listenaddress'): return True
    return False
def check(words, where):
    for word in words:
        for name in ('SSHD_OPTS', 'OPTIONS'):
            if word.startswith(name + '=') and risky(word[len(name) + 1:]):
                raise SystemExit(f'{where} 的 {name} 指定了 SSH 端口、监听地址或配置文件，需人工处理。')
check(shlex.split(sys.argv[1]), 'SSH 服务')
for path in ('/etc/default/ssh', '/etc/sysconfig/sshd'):
    p = pathlib.Path(path)
    if p.exists():
        for line in p.read_text().splitlines():
            check(shlex.split(line, comments=True), path)
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
    ssh_reload || return 1
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
    selinux_allow_ports "$target_ports"
    write_f2b "$target_ports"
    ssh_reload
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
    local new=$1 old combined whitelist source
    valid_port "$new" || die '请输入 1 到 65535 的端口。'
    ssh_preflight
    old=$(ssh_ports)
    [[ ,$old, != *,$new,* ]] || die '该端口已经是 SSH 监听端口。'
    [[ -z $(ss -H -lnt "sport = :$new") ]] || die '新 TCP 端口已被其他程序使用。'
    load_rules
    [[ -z $(rule_info --list | awk -F'\t' -v p="$new" '$1 == p && $2 == "tcp" && $4 != "SSH"') ]] ||
        die "新端口 $new 已有普通 TCP 放行规则，请先确认用途，在「端口访问管理」里关闭它。"
    whitelist=$(ssh_whitelist "$old")
    printf '\nSSH 端口：%s → %s\n' "$old" "$new"
    printf '迁移分两步：先让新旧端口同时可用；你用新端口登录成功后，再关闭旧端口。\n'
    [[ -z $whitelist ]] || printf '新端口沿用 SSH 现在的来源限制：只允许 %s。\n' "${whitelist//,/、}"
    printf '开始前请确认：服务商安全组（云防火墙）已放行 %s/TCP，并且不要关闭当前窗口。\n\n' "$new"
    confirm '开始第一步？' || cancel '没有修改任何配置'
    ssh_snapshot
    start_transaction
    for source in ${whitelist//,/ }; do port_rule add "$new" tcp "$source" SSH; done
    combined=$(printf '%s,%s\n' "$old" "$new" | tr ',' '\n' | sort -nu | paste -sd, -)
    apply_ssh_ports "$combined"
    mkdir -p "$STATE_DIR"
    printf '%s\n%s\n%s\n' "$backup_dir" "$old" "$new" > "$PENDING_FILE.tmp"
    mv "$PENDING_FILE.tmp" "$PENDING_FILE"
    end_transaction
    prune_backups
    printf '\n第一步完成：新端口 %s 已开始监听，旧端口 %s 仍然可用，Fail2ban 同时保护两者。\n\n' "$new" "$old"
    printf '下一步：保留当前窗口，在你自己电脑上新开一个终端执行：\n\n    %s\n\n' "$(ssh_login_hint "$new")"
    printf '登录成功后，在新窗口里运行 vpsfw，进入「SSH 管理 → 完成端口迁移」，选「确认迁移」。\n'
    printf '如果新端口连不上，回到当前窗口，在同一个地方选「回退迁移」。\n'
}
ssh_finish() {
    read_pending
    if [[ ${session_port:-} != "$pending_new" ]]; then
        printf '\n当前窗口是通过 %s 连接的，不能在这里确认。\n' "${session_port:-控制台}" >&2
        printf '请先用新端口登录（%s），在新窗口里到「SSH 管理」确认。\n' "$(ssh_login_hint "$pending_new")" >&2
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
    local p
    IFS=, read -r -a old_array <<< "$pending_old"
    for p in "${old_array[@]}"; do delete_ssh_rules "$p"; done
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
    if [[ -z $(ssh_rule_sources "$pending_new") ]]; then
        :
    elif grep -qs "^### tuple ### allow tcp $pending_new " "$pending_backup/ufw/user.rules" "$pending_backup/ufw/user6.rules"; then
        printf '%s/tcp 的放行规则在迁移前就已存在，保留不动。\n' "$pending_new"
    elif ! (verify_ssh_ports "$pending_old") 2>/dev/null; then
        printf '旧端口 %s 没有确认恢复监听，%s/tcp 的放行规则先保留，请检查后手动处理。\n' "$pending_old" "$pending_new" >&2
    elif delete_ssh_rules "$pending_new"; then
        printf '已删除 %s/tcp 的防火墙放行；服务商安全组里的这条放行也可以删掉。\n' "$pending_new"
    else
        printf '删除 %s/tcp 的防火墙放行失败，请用 ufw status numbered 查看后手动删除。\n' "$pending_new" >&2
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
# Status rows shared by the status page and the firewall menu.
firewall_row() {
    local raw fw='● 未安装' color=$c_err note='请先初始化（主菜单 1）' policy_in policy_out ipv6
    if command -v ufw >/dev/null; then
        raw=$(ufw status 2>/dev/null) || raw=''
        policy_in=$(sed -n 's/^DEFAULT_INPUT_POLICY="\(.*\)"$/\1/p' /etc/default/ufw)
        policy_out=$(sed -n 's/^DEFAULT_OUTPUT_POLICY="\(.*\)"$/\1/p' /etc/default/ufw)
        if grep -q '^IPV6=yes' /etc/default/ufw; then ipv6='IPv6 开启'; else ipv6='IPv6 未开启'; fi
        if [[ $policy_in == ACCEPT ]]; then policy_in='默认放行所有入站'; else policy_in='拒绝未放行的入站'; fi
        if [[ $policy_out == ACCEPT ]]; then policy_out='允许出站'; else policy_out='限制出站'; fi
        case "$raw" in
            'Status: active'*) fw='● 已启用'; color=$c_ok; note="$policy_in · $policy_out · $ipv6" ;;
            'Status: inactive'*) fw='● 未启用'; color=$c_warn; note='所有端口都对外开放；放行规则已保存，启用后才生效' ;;
            *) fw='● 状态异常'; color=$c_warn; note='请运行 ufw status 查看' ;;
        esac
    fi
    status_row 防火墙 "$fw" "$color" "$note"
}
ping_row() {
    command -v ufw >/dev/null || return 0
    ping_state
    case $REPLY in
        blocked) status_row Ping '● 已禁止' "$c_ok" '别人 ping 不通这台服务器' ;;
        allowed) status_row Ping '允许' '' '别人可以 ping 通这台服务器' ;;
        mixed) status_row Ping '● 部分禁止' "$c_warn" 'IPv4 和 IPv6 的设置不一致' ;;
        *) status_row Ping '未知' "$c_warn" 'UFW 的 ping 规则被手动改过' ;;
    esac
}
# Group the allow rules per port into access_entries: port<TAB>proto<TAB>sources<TAB>is-SSH.
access_load() {
    local ssh line
    load_rules
    ssh=$(ssh_ports 2>/dev/null) || ssh=''
    access_entries=()
    while IFS= read -r line; do
        [[ -z $line ]] || access_entries+=("$line")
    done < <(rule_info --access "$ssh${session_port:+,$session_port}")
}
# Who can reach each port; numbered when $1 is 1.
access_print() {
    local numbered=${1:-0} line rp rproto rsources rssh name who n=0
    if (( ${#access_entries[@]} == 0 )); then printf '  %s还没有放行任何端口%s\n' "$c_dim" "$c_off"; return 0; fi
    printf '  %s' "$c_dim"
    (( ! numbered )) || pad 编号 6
    printf '%s%s谁能访问%s\n' "$(pad 端口 14)" "$(pad 协议 9)" "$c_off"
    for line in "${access_entries[@]}"; do
        IFS=$'\t' read -r rp rproto rsources rssh <<< "$line"
        n=$((n + 1)); name=${rp/:/-}
        (( ! rssh )) || name+=' (SSH)'
        access_label "$rsources" 44; who=$REPLY
        printf '  '
        (( ! numbered )) || pad "$n" 6
        printf '%s%s%s\n' "$(pad "$name" 14)" "$(pad "$(proto_label "$rproto")" 9)" "$who"
    done
}
show_status() {
    set_colors
    local ssh ssh_color='' ssh_note f2b_note others
    ssh=$(ssh_ports 2>/dev/null) || ssh=''
    if [[ -f $PENDING_FILE ]]; then ssh_color=$c_warn; ssh_note='迁移待确认：从新端口登录后到「SSH 管理」确认'
    elif [[ -n ${session_port:-} ]]; then ssh_note="当前连接 $session_port"
    else ssh_note='当前在控制台'; fi
    read_f2b
    case "$f2b_state" in
        *保护中) f2b_note="封禁中 $(f2b_field 'Currently banned') 个 · 累计 $(f2b_field 'Total banned') 次" ;;
        *未运行) f2b_note='SSH 登录保护没有运行，可在「Fail2ban 管理」里同步' ;;
        *) f2b_note='请先初始化（主菜单 1）' ;;
    esac

    section '防护状态'
    firewall_row
    status_row SSH "${ssh:-未知}" "$ssh_color" "$ssh_note"
    status_row Fail2ban "$f2b_state" "$f2b_color" "$f2b_note"
    ping_row

    if command -v ufw >/dev/null; then
        access_load
        section "端口访问（${#access_entries[@]} 个）"
        access_print
        others=$(rule_info --other)
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
# Fail2ban details for its menu; sets f2b_sync=1 when the jail needs resyncing.
show_f2b() {
    set_colors
    read_f2b
    local ssh ports maxretry findtime bantime
    f2b_sync=0
    ssh=$(ssh_ports 2>/dev/null) || ssh=''
    printf '\n'
    if [[ -z $f2b_status ]]; then
        if [[ $f2b_state == *未安装 ]]; then
            status_row 状态 "$f2b_state" "$f2b_color" '请先初始化（主菜单 1）'
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
import glob, gzip, json, os, re, subprocess, sys, time, unicodedata
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
                          '-o', 'json', '--no-pager'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         universal_newlines=True).stdout
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
    m = penalty.search(message)
    if m:
        dropped[m.group(1)] += 1
        continue
    conn = connections[(entry.get('_BOOT_ID'), entry.get('_PID'))]
    m = accepted.search(message)
    if m:
        method, user, ip = m.groups()
        successes.append((when, user, ip, {'publickey': '密钥', 'password': '密码'}.get(method, method)))
        conn['accepted'] = True
        continue
    for pattern in (failed, invalid, closed):
        m = pattern.search(message)
        if m:
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
# Debian 10 and RHEL-family systems keep the journal in memory unless /var/log/journal exists.
if not os.path.isdir('/var/log/journal'):
    print(f'  {dim}这台服务器的系统日志没有保存到磁盘，只能看到这次开机以来的记录。{off}')
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
                ban = re.search(r'\[sshd\] Ban (\S+)', line)
                if when >= since and ban: bans.append(ban.group(1))
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
# ACCEPT or DROP from a rules file, or nothing when the line is missing or its copies disagree
# (older ufw repeats the IPv6 line).
ping_rule() {
    local actions
    actions=$(grep -F -x -e "$2 ACCEPT" -e "$2 DROP" "$1" 2>/dev/null | awk '{print $NF}' | sort -u) || true
    if [[ $actions == ACCEPT || $actions == DROP ]]; then printf '%s\n' "$actions"; fi
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
    [[ $(ufw status) == 'Status: active'* ]] || printf '防火墙当前未启用，设置已保存，启用防火墙后才生效。\n'
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
    # Debian prints P, RHEL-family systems PS.
    if [[ ${fields[1]:-} == P || ${fields[1]:-} == PS ]]; then REPLY="有密码（${fields[2]:-?} 修改）"; else REPLY='没有密码'; fi
}
# Public keys in an authorized_keys file: list them, check a pasted line, or remove one by number.
key_tool() {
    python3 - "$@" <<'PY'
import os, subprocess, sys, tempfile
op, *args = sys.argv[1:]
def fingerprint(line):
    with tempfile.NamedTemporaryFile('w', suffix='.pub') as f:
        f.write(line + '\n'); f.flush()
        result = subprocess.run(['ssh-keygen', '-l', '-f', f.name], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, universal_newlines=True)
    if result.returncode or not result.stdout.strip(): return None
    _, fp, *rest = result.stdout.split()
    return fp, (rest[-1].strip('()') if rest else '?'), ' '.join(rest[:-1])
def keys(path):
    try: lines = open(path).read().splitlines()
    except FileNotFoundError: lines = []
    found = []
    for i, line in enumerate(lines):
        if line.strip() and not line.lstrip().startswith('#'):
            info = fingerprint(line.strip())
            if info: found.append((i, info))
    return lines, found
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
# Header of the SSH menu: port, who may log in, password login and this connection.
ssh_status() {
    local user=${auth_user:-${SUDO_USER:-root}} current pa root_login how whitelist
    current=$(ssh_ports 2>/dev/null) || current=''
    pa=$(sshd_value passwordauthentication) || pa=''
    root_login=$(sshd_value permitrootlogin) || root_login=''
    printf '\n'
    if [[ -f $PENDING_FILE ]]; then status_row 'SSH 端口' "${current:-未知}" "$c_warn" '迁移待确认：从新端口登录后选 1 完成'
    else status_row 'SSH 端口' "${current:-未知}" '' "${session_port:+当前连接 $session_port}"; fi
    if command -v ufw >/dev/null && [[ -n $current ]]; then
        whitelist=$(ssh_whitelist "$current")
        if [[ -n $whitelist ]]; then
            access_label "$whitelist" 44
            status_row 登录来源 '● 指定 IP' "$c_ok" "${REPLY#只允许 }"
        else
            status_row 登录来源 '所有 IP' '' '要限制来源，到「端口访问管理」修改 SSH 那一行'
        fi
    fi
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
    local want=$1 expected=no current content backup='' user with_keys='' target=$AUTH_CONF kbd main=/etc/ssh/sshd_config
    [[ $want == off ]] || expected=yes
    ssh_preflight pending
    # Without an sshd_config.d include the setting goes into a marked block at the top of the main file,
    # where it is read before anything else.
    grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$main" || target=$main
    # OpenSSH before 8.7 only knows the old name of the keyboard-interactive switch.
    kbd=ChallengeResponseAuthentication
    if sshd -T 2>/dev/null | grep -q '^kbdinteractiveauthentication '; then kbd=KbdInteractiveAuthentication; fi
    current=$(sshd_value passwordauthentication) || current=''
    if [[ $current == "$expected" ]]; then
        if [[ $want == off ]]; then printf 'SSH 密码登录本来就是关闭的。\n'; else printf 'SSH 密码登录本来就是允许的。\n'; fi
        return 0
    fi
    if [[ $want == off ]]; then
        # Never close password login unless someone can still get in with a key.
        if [[ -n ${client_addr:-} ]]; then
            session_auth
            [[ $auth_method == publickey ]] || die "当前窗口不是用密钥登录的（${auth_method:-查不到登录方式}）。请先在「SSH 管理 → 管理公钥」里添加公钥，用密钥登录一次，再在那个窗口里关闭密码登录。"
        else
            for user in $(login_users); do
                (( $(key_count "$user") == 0 )) || with_keys+="${with_keys:+、}$user"
            done
            [[ -n $with_keys ]] || die '服务器上没有任何用户配置了公钥，关闭密码登录后就没人能登录了。'
            printf '当前不是 SSH 连接。这些用户有公钥，关闭后只能用它们登录：%s\n' "$with_keys"
        fi
        printf '关闭后所有用户（包括 root）都只能用密钥登录，猜密码的攻击会全部失效；已经连着的窗口不受影响。\n'
        confirm '关闭 SSH 密码登录？' y || cancel
        content=$'# Managed by vpsfw: SSH password login is off.\nPasswordAuthentication no\n'"$kbd no"$'\n'
    else
        printf '打开后用户可以用密码登录 SSH，root 是否能用密码仍按原来的设置。\n'
        confirm '打开 SSH 密码登录？' || cancel
        content=$'# Managed by vpsfw: SSH password login is on.\nPasswordAuthentication yes\n'
    fi
    [[ ! -e $target ]] || backup=$(cat "$target"; printf x)
    if [[ $target == "$AUTH_CONF" ]]; then
        # Files in sshd_config.d are read before the main config and the first value wins, so this one takes effect.
        printf '%s' "$content" > "$AUTH_CONF.tmp" && chmod 644 "$AUTH_CONF.tmp" && mv -f "$AUTH_CONF.tmp" "$AUTH_CONF"
    else
        python3 - "$main" "$content" <<'PY'
import os, re, sys
path, content = sys.argv[1:]
text = open(path).read()
text = re.sub(r'^# BEGIN VPSFW AUTH\n.*?^# END VPSFW AUTH\n?', '', text, flags=re.M | re.S)
block = '# BEGIN VPSFW AUTH\n' + content + '# END VPSFW AUTH\n'
tmp = path + '.vpsfw-tmp'
with open(tmp, 'w') as f: f.write(block + text)
os.chmod(tmp, os.stat(path).st_mode & 0o777); os.replace(tmp, path)
PY
    fi
    if ! sshd -t || ! ssh_reload || [[ $(sshd_value passwordauthentication) != "$expected" ]]; then
        if [[ -n $backup ]]; then printf '%s' "${backup%x}" > "$target"; else rm -f "$target"; fi
        sshd -t && ssh_reload || true
        die '修改没有生效，已恢复原来的设置。'
    fi
    if [[ $want == off ]]; then printf 'SSH 密码登录已关闭，现在只能用密钥登录。\n'
    else printf 'SSH 密码登录已打开。\n'; fi
}
menu_unban() {
    local ip list
    list=" $(f2b_field 'Banned IP list') "
    while true; do
        printf '\n'
        ask ip '要解封哪个 IP？（回车返回）: ' && [[ -n $ip ]] || return 0
        [[ $list != *" $ip "* ]] || break
        printf '%s 不在封禁名单里。\n' "$ip"
    done
    if fail2ban-client set sshd unbanip "$ip" >/dev/null; then printf '已解封 %s。\n' "$ip"
    else printf '解封失败，请查看 Fail2ban 状态。\n'; fi
}
ports_command() {
    local op=${1:-list}
    command -v ufw >/dev/null || die '还没有初始化：请先在菜单选 1，或运行 vpsfw install。'
    load_rules
    case "$op" in
        list)
            (( $# <= 1 )) || die 'ports list 无需其他参数。'
            set_colors; access_load; printf '\n'; access_print
            [[ -z $(rule_info --other) ]] || printf '\n  %s另有不归本工具管理的规则，用 vpsfw status 查看。%s\n' "$c_dim" "$c_off"
            printf '\n' ;;
        add|delete) ports_edit "$@" ;;
        set|close|change) ports_access "$@" ;;
        *) die 'ports 支持 list、set、add、delete、change、close。' ;;
    esac
}
# add/delete: one source more or less on each of the ports.
ports_edit() {
    local op=$1 list=$2 proto source p protocol comment covering lookup_status
    (( $# >= 2 && $# <= 4 )) || die '用法：ports add/delete 端口列表 [协议] [来源]'
    proto=${3:-tcp}; source=${4:-any}
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
                [[ $comment != SSH ]] || die "$p/$protocol 是 SSH 入口，请到「SSH 管理」里改。"
            else
                lookup_status=$?
                (( lookup_status == 1 )) || die '无法明确识别现有规则。'
                [[ $op == add ]] || die "找不到 $p/${protocol}（来源 $(source_label "$source")）的放行规则。用 vpsfw ports list 查看现有规则。"
            fi
        done
    done
    if [[ $op == add ]]; then printf '\n添加放行：%s' "$(IFS=,; printf '%s' "${ports[*]}")"
    else printf '\n删除放行：%s' "$(IFS=,; printf '%s' "${ports[*]}")"; fi
    printf '  %s  来源 %s\n' "$(proto_label "$proto")" "$(source_label "$source")"
    backup_ufw
    for p in "${ports[@]}"; do
        for protocol in "${protocols[@]}"; do
            if [[ $op == delete ]]; then
                port_rule delete "$p" "$protocol" "$source"
                printf '  ✓ 已删除 %s/%s\n' "$p" "$protocol"
            elif existing_rule "$p" "$protocol" "$source"; then
                printf '  · %s/%s 已经放行，跳过\n' "$p" "$protocol"
            else
                port_rule add "$p" "$protocol" "$source"
                printf '  ✓ 已放行 %s/%s\n' "$p" "$protocol"
            fi
        done
    done
    load_rules
    prune_backups
    # Point out rules that still decide access, instead of a generic disclaimer.
    for p in "${ports[@]}"; do
        for protocol in "${protocols[@]}"; do
            if [[ $op == add && $source != any ]]; then
                covering=$(covering_rules "$p" "$protocol" any)
                [[ -z $covering ]] || printf '\n注意：%s/%s 还有对所有 IP 开放的规则，只允许 %s 不会生效：\n%s\n' "$p" "$protocol" "$source" "$covering"
            elif [[ $op == delete ]]; then
                covering=$(covering_rules "$p" "$protocol")
                [[ -z $covering ]] || printf '\n注意：%s/%s 仍被下面的规则放行：\n%s\n' "$p" "$protocol" "$covering"
            fi
        done
    done
    [[ $op == delete ]] || access_hints
}
# set: each port lets in exactly the given sources ("any" = all IPs); close: delete every rule of the
# ports; change: move one port's rules to another port. New rules go in before old ones are deleted,
# so addresses that stay allowed never lose access in between.
ports_access() {
    local op=$1 list=${2:-} proto target='' new='' ssh p protocol sources comment covering ssh_limited=0
    case "$op" in
        set)
            (( $# == 4 )) || die '用法：ports set 端口列表 协议 来源列表|any'
            proto=$3; target=$(normalize_sources "$4") || die '来源地址无效。' ;;
        close)
            (( $# == 2 || $# == 3 )) || die '用法：ports close 端口列表 [协议]'
            proto=${3:-tcp} ;;
        change)
            (( $# == 3 || $# == 4 )) || die '用法：ports change 旧端口 新端口 [协议]'
            proto=${4:-tcp}; list=$(clean_ports "$list"); new=$(clean_ports "$3")
            valid_spec "$list" && valid_spec "$new" || die '换端口每次只能换一个端口或范围。'
            [[ ${new%%:*} != "${new##*:}" ]] || new=${new%%:*}
            [[ ${list%%:*} != "${list##*:}" ]] || list=${list%%:*}
            [[ $list != "$new" ]] || die '新旧端口相同。' ;;
    esac
    proto=$(printf '%s' "$proto" | tr '[:upper:]' '[:lower:]')
    [[ $proto == tcp || $proto == udp || $proto == both ]] || die "协议只能是 tcp、udp 或 both（两者都要），收到：$proto"
    parse_ports "$list"
    local protocols=(tcp udp)
    [[ $proto == both ]] || protocols=("$proto")
    ssh=$(ssh_ports) || die '无法读取 SSH 配置，暂不修改规则。'
    ssh=",$ssh,${session_port:-},"
    # Validate the entire batch before the first mutation.
    for p in "${ports[@]}"; do
        if [[ $ssh == *",$p,"* && $proto != udp ]]; then
            [[ $op == set ]] || die "$p 是 SSH 端口，不能在这里关闭或换号；换 SSH 端口请到「SSH 管理 → 修改 SSH 端口」。"
            [[ $proto == tcp ]] || die "SSH 端口 $p 只用 TCP，请把协议写成 tcp。"
            [[ ! -f $PENDING_FILE ]] || die 'SSH 端口迁移还没完成，请先到「SSH 管理」确认或回退，再限制 SSH 的来源。'
            check_session_allowed "$p" "$target"
            [[ $target == any ]] || ssh_limited=1
            continue
        fi
        for protocol in "${protocols[@]}"; do
            check_ssh_collision "$p" "$protocol"
            [[ $op == set || -n $(port_sources "$p" "$protocol") ]] || die "${p/:/-}/$protocol 没有放行规则，用 vpsfw ports list 查看。"
            if [[ $op == change ]]; then
                check_ssh_collision "$new" "$protocol"
                [[ -z $(port_sources "$new" "$protocol") ]] ||
                    die "新端口 ${new/:/-}/$protocol 已经有放行规则，请先关闭它，或者直接修改它允许的 IP。"
            fi
        done
    done
    case "$op" in
        set) access_label "$target" 200; printf '\n%s  %s  →  %s\n' "$(IFS=,; printf '%s' "${ports[*]//:/-}")" "$(proto_label "$proto")" "$REPLY" ;;
        close) printf '\n关闭：%s  %s\n' "$(IFS=,; printf '%s' "${ports[*]//:/-}")" "$(proto_label "$proto")" ;;
        change) printf '\n换端口：%s → %s  %s\n' "${list/:/-}" "${new/:/-}" "$(proto_label "$proto")" ;;
    esac
    backup_ufw
    if [[ $op == change ]]; then
        # Open the new port for every protocol before closing anything on the old one.
        for protocol in "${protocols[@]}"; do
            sources=$(port_sources "$list" "$protocol" | paste -sd, -)
            sync_sources "$new" "$protocol" "$sources"
        done
        for protocol in "${protocols[@]}"; do sync_sources "$list" "$protocol" ''; done
    fi
    for p in "${ports[@]}"; do
        comment=''
        [[ $ssh != *",$p,"* || $proto != tcp ]] || comment=SSH
        for protocol in "${protocols[@]}"; do
            case "$op" in
                set) sync_sources "$p" "$protocol" "$target" "$comment" ;;
                close) sync_sources "$p" "$protocol" '' ;;
            esac
        done
    done
    load_rules
    prune_backups
    for p in "${ports[@]}"; do
        for protocol in "${protocols[@]}"; do
            if [[ $op == set && $target != any ]]; then
                covering=$(covering_rules "$p" "$protocol" any)
                [[ -z $covering ]] || printf '\n注意：%s/%s 还被下面这条对所有 IP 开放的规则放行，只允许指定 IP 不会生效：\n%s\n' "${p/:/-}" "$protocol" "$covering"
            elif [[ $op != set ]]; then
                covering=$(covering_rules "$p" "$protocol")
                [[ -z $covering ]] || printf '\n注意：%s/%s 仍被下面的规则放行：\n%s\n' "${p/:/-}" "$protocol" "$covering"
            fi
        done
    done
    if (( ssh_limited )); then
        printf '\nSSH 现在只允许名单里的 IP 登录。家里宽带的 IP 可能会变，变了就连不上，只能从服务商网页控制台进去改。\n'
    fi
    [[ $op == close ]] || { [[ $op != change ]] || ports=("$new"); access_hints; }
}
# After opening ports: services not listening yet, the firewall switch and the cloud security group.
access_hints() {
    local p protocol idle=''
    for p in "${ports[@]}"; do
        for protocol in "${protocols[@]}"; do
            [[ -n $(ss -H -ln"${protocol:0:1}" "sport >= :${p%%:*} and sport <= :${p##*:}" 2>/dev/null) ]] ||
                idle+="${idle:+、}${p/:/-}/$protocol"
        done
    done
    [[ -z $idle ]] || printf '\n目前没有程序在监听 %s，服务启动后外部才能访问。\n' "$idle"
    if [[ $(ufw status) != 'Status: active'* ]]; then
        printf '\n防火墙当前未启用，规则已保存，启用防火墙后才生效。\n'
    else
        printf '\n服务商安全组（云防火墙）也需要放行对应端口，外部才能访问。\n'
    fi
}
ufw_switch() {
    command -v ufw >/dev/null || die '还没有初始化：请先在菜单选 1，或运行 vpsfw install。'
    if [[ $1 == enable ]]; then
        local p current sources
        current=$(ssh_ports)
        [[ -n $current ]] || die '无法识别 SSH 端口，拒绝启用。'
        load_rules
        sources=$(port_sources "${session_port:-0}" tcp | paste -sd, -)
        [[ -z $sources ]] || check_session_allowed "$session_port" "$sources"
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
menu_colors() {
    cyan='' purple='' reset='' bold='' dim=''
    if [[ -t 1 && ${TERM:-dumb} != dumb && ${NO_COLOR+x} != x ]]; then
        cyan=$'\033[36m'; purple=$'\033[34m'; reset=$'\033[0m'; bold=$'\033[1m'; dim=$'\033[90m'
    fi
}
clear_screen() { if [[ -t 1 && ${TERM:-dumb} != dumb ]]; then printf '\033[2J\033[H'; fi; }
# Terminal width decides between two columns and one (wide), and the length of the rules (menu_span).
menu_layout() {
    columns=$(tput cols 2>/dev/null) || columns=${COLUMNS:-80}
    [[ $columns =~ ^[0-9]+$ ]] || columns=80
    menu_span=60 wide=1
    if (( columns < 64 )); then
        wide=0; menu_span=$((columns - 4))
        (( menu_span >= 24 )) || menu_span=24
    fi
}
MENU_LABELS=('初始化防护' '状态总览' '端口访问管理' 'SSH 管理' 'Fail2ban 管理' '防火墙与 Ping')
menu_draw() {
    local fw=$1 ban=$2 current=$3 i padding
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
    printf '\n  %sVPS Firewall  ·  %s %s%s\n' "$bold" "${NAME%% *}" "${VERSION_ID:-}" "$reset"
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
    if (( wide )); then
        for ((i=0;i<3;i++)); do
            menu_item "$((i+1))" "${MENU_LABELS[i]}"
            menu_width "${MENU_LABELS[i]}"; padding=$((28 - 4 - REPLY))
            # The first column already supplied the row indentation.
            printf '%*s    %s%2s.%s %s\n\n' "$padding" '' "$cyan" "$((i+4))" "$reset" "${MENU_LABELS[i+3]}"
        done
    else
        for ((i=0;i<6;i++)); do menu_item "$((i+1))" "${MENU_LABELS[i]}"; printf '\n\n'; done
    fi
    menu_rule
    menu_item 0 '退出'; printf '\n'; menu_rule
    if [[ -f $PENDING_FILE ]]; then
        printf '\n  %sSSH 迁移待确认%s\n  请从新端口登录，再进入 4「SSH 管理」确认。\n' "$cyan" "$reset"
    elif [[ $fw == 未安装 ]]; then
        printf '\n  %s尚未初始化%s\n  新服务器请先选择 1。\n' "$cyan" "$reset"
    fi
    printf '\n'
}
# Top of a second-level screen; the caller prints its status below.
sub_title() {
    clear_screen; menu_layout
    printf '\n  %s%s%s\n' "$bold" "$1" "$reset"
    menu_rule
}
# The numbered actions of a second-level screen, then 0 to go back.
sub_actions() {
    local i=0 label
    printf '\n'; menu_rule; printf '\n'
    for label in "$@"; do i=$((i + 1)); menu_item "$i" "$label"; printf '\n\n'; done
    menu_rule
    menu_item 0 '返回主菜单'; printf '\n'; menu_rule
    printf '\n'
}
# Read a choice from 1 to $1 into choice; returns 1 for 0 or end of input.
menu_choose() {
    while true; do
        ask choice "  请选择 [0-$1]: " || return 1
        case "$choice" in
            0|q|Q) return 1 ;;
            '') ;;
            *)
                if [[ $choice =~ ^[0-9]+$ ]] && (( 10#$choice >= 1 && 10#$choice <= $1 )); then
                    choice=$((10#$choice)); return 0
                fi
                printf '  没有这个选项，请输入 0 到 %s。\n' "$1" ;;
        esac
    done
}
pause() { local reply; ask reply $'\n按回车返回……' || true; }
not_ready() {
    command -v ufw >/dev/null && return 1
    printf '\n还没有初始化，请先在主菜单选 1。\n'; pause
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
# Who may reach a port: REPLY becomes "any" or a comma list of addresses.
ask_who() {
    local value
    printf '\n谁能访问：\n  1) 所有 IP\n  2) 只允许指定的 IP\n'
    while ask value '请选择 [回车 = 1]: '; do
        case ${value:-1} in
            1) REPLY=any; return 0 ;;
            2) ask_ips; return ;;
            *) printf '请输入 1 或 2。\n' ;;
        esac
    done
    return 1
}
# Addresses or networks separated by commas or spaces; REPLY holds them normalised.
ask_ips() {
    local value
    printf '\n填 IP 或网段，例如 203.0.113.8 或 198.51.100.0/24，多个用逗号分隔。\n'
    [[ -z ${client_addr:-} ]] || printf '你现在连接用的 IP 是 %s。\n' "$client_addr"
    while ask value 'IP（回车返回）: ' && [[ -n $value ]]; do
        if ! REPLY=$(normalize_sources "$value"); then continue; fi
        [[ $REPLY != any ]] && return 0
        printf '这里填具体的 IP；要所有 IP 都能访问，请用「端口改成所有 IP 可访问」。\n'
    done
    return 1
}
# Read numbers from 1 to $2 into picked (0-based); $3=1 allows several, e.g. "1,3" or "1 3".
ask_numbers() {
    local value item seen items
    while ask value "$1" && [[ -n $value ]]; do
        value=${value//，/ }
        read -r -a items <<< "${value//,/ }"
        picked=(); seen=' '
        for item in ${items[@]+"${items[@]}"}; do
            if [[ ! $item =~ ^[0-9]+$ ]] || (( 10#$item < 1 || 10#$item > $2 )); then
                printf '没有编号 %s，请输入 1 到 %s 之间的编号。\n' "$item" "$2"; picked=(); break
            fi
            [[ $seen == *" $((10#$item)) "* ]] || picked+=($((10#$item - 1)))
            seen+="$((10#$item)) "
        done
        (( ${#picked[@]} )) || continue
        if (( ${3:-0} == 0 && ${#picked[@]} > 1 )); then printf '一次只能选一个。\n'; continue; fi
        return 0
    done
    return 1
}
# Pick entries of the port list; entry sets e_port, e_proto, e_sources, e_ssh and e_name.
pick_entry() {
    if (( ${#access_entries[@]} == 0 )); then printf '\n还没有放行任何端口。\n'; return 1; fi
    printf '\n'
    ask_numbers "$1" "${#access_entries[@]}" "${2:-0}"
}
entry() {
    IFS=$'\t' read -r e_port e_proto e_sources e_ssh <<< "${access_entries[$1]}"
    e_name="${e_port/:/-} $(proto_label "$e_proto")"
    (( ! e_ssh )) || e_name="SSH ${e_name}"
}
access_add() {
    local list proto sources p protocol taken=''
    printf '\n放行新端口。多个端口用逗号分隔，范围写 8000-8010。\n\n'
    ask_ports '端口（回车返回）: ' || return 0; list=$REPLY
    ask_proto || return 0; proto=$REPLY
    local protocols=(tcp udp)
    [[ $proto == both ]] || protocols=("$proto")
    for p in ${list//,/ }; do
        for protocol in "${protocols[@]}"; do
            [[ -z $(port_sources "$p" "$protocol") ]] || taken+="${taken:+、}${p/:/-}/$protocol"
        done
    done
    if [[ -n $taken ]]; then
        printf '\n%s 已经放行过了。要改谁能访问，请用「修改某个端口允许的 IP」。\n' "$taken"; return 0
    fi
    ask_who || return 0; sources=$REPLY
    access_label "$sources" 200
    printf '\n将放行：%s  %s  %s\n' "${list//:/-}" "$(proto_label "$proto")" "$REPLY"
    confirm '确认放行？' y || { printf '已取消。\n'; return 0; }
    bash "$SELF" ports set "$list" "$proto" "$sources" || true
}
access_edit() {
    local choice ips=() keep='' i n
    pick_entry '修改哪个端口允许的 IP？输入编号（回车返回）: ' || return 0
    entry "${picked[0]}"
    [[ ,$e_sources, == *,any,* ]] || IFS=, read -r -a ips <<< "$e_sources"
    if (( ${#ips[@]} == 0 )); then
        printf '\n%s 现在所有 IP 都能访问。填上 IP 以后，就只有这些 IP 能访问。\n' "$e_name"
        choice=1
    else
        printf '\n%s 现在只允许：\n\n' "$e_name"
        for i in "${!ips[@]}"; do printf '  %s%s\n' "$(pad "$((i + 1))" 4)" "${ips[i]}"; done
        printf '\n  1) 添加 IP\n  2) 移除 IP\n\n'
        while true; do
            ask choice '请选择（回车返回）: ' && [[ -n $choice ]] || return 0
            [[ $choice != 1 && $choice != 2 ]] || break
            printf '请输入 1 或 2。\n'
        done
    fi
    if [[ $choice == 1 ]]; then
        ask_ips || return 0
        keep=$(printf '%s\n' ${ips[@]+"${ips[@]}"} ${REPLY//,/ } | awk 'NF && !seen[$0]++' | paste -sd, -)
        access_label "$keep" 200
        printf '\n改完后 %s %s。\n' "$e_name" "$REPLY"
    else
        ask_numbers '要移除第几个？多个用逗号分隔（回车返回）: ' "${#ips[@]}" 1 || return 0
        for i in "${!ips[@]}"; do
            [[ " ${picked[*]} " == *" $i "* ]] || keep+=${keep:+,}${ips[i]}
        done
        if [[ -z $keep ]]; then
            if (( e_ssh )); then
                printf '\nSSH 至少要留一个 IP，不然谁都登录不上。想让所有 IP 都能连，请用「端口改成所有 IP 可访问」。\n'; return 0
            fi
            printf '\n全部移除后没有 IP 能访问 %s，等于关闭这个端口。\n' "$e_name"
            confirm '确认关闭？' || { printf '已取消。\n'; return 0; }
            bash "$SELF" ports close "$e_port" "$e_proto" || true
            return 0
        fi
        access_label "$keep" 200
        printf '\n改完后 %s %s。\n' "$e_name" "$REPLY"
    fi
    if (( e_ssh )); then
        ( check_session_allowed "$e_port" "$keep" ) || return 0
        printf '限制以后，从别的网络（换了宽带、用手机热点）就登录不上 SSH 了。\n'
    fi
    confirm '确认修改？' y || { printf '已取消。\n'; return 0; }
    bash "$SELF" ports set "$e_port" "$e_proto" "$keep" || true
}
access_open() {
    pick_entry '哪个端口改成所有 IP 可访问？输入编号（回车返回）: ' || return 0
    entry "${picked[0]}"
    if [[ ,$e_sources, == *,any,* ]]; then printf '\n%s 本来就是所有 IP 都能访问。\n' "$e_name"; return 0; fi
    printf '\n%s 将对所有 IP 开放，原来的名单（%s）用不上了，会一并删除。\n' "$e_name" "${e_sources//,/、}"
    (( ! e_ssh )) || printf 'SSH 对所有 IP 开放后，靠 Fail2ban 挡暴力破解；建议只用密钥登录。\n'
    confirm '确认？' y || { printf '已取消。\n'; return 0; }
    bash "$SELF" ports set "$e_port" "$e_proto" any || true
}
access_move() {
    local value new
    pick_entry '要换哪个端口？输入编号（回车返回）: ' || return 0
    entry "${picked[0]}"
    if (( e_ssh )); then
        printf '\nSSH 端口请到「SSH 管理 → 修改 SSH 端口」里换，那里会先确认新端口能登录，再关旧端口。\n'; return 0
    fi
    access_label "$e_sources" 200
    printf '\n原端口：%s  %s\n' "$e_name" "$REPLY"
    while true; do
        ask value '新端口或范围（回车返回）: ' && [[ -n $value ]] || return 0
        new=$(clean_ports "$value")
        valid_spec "$new" && [[ $new != "$e_port" ]] && break
        printf '请输入一个与原来不同的端口（1-65535）或范围，例如 8443 或 8000-8010。\n'
    done
    printf '\n将把 %s 换成 %s，谁能访问保持不变（先放行新端口，再关闭旧端口）。\n' "${e_port/:/-}" "${new/:/-}"
    confirm '确认？' y || { printf '已取消。\n'; return 0; }
    bash "$SELF" ports change "$e_port" "$new" "$e_proto" || true
}
access_close() {
    local i targets=()
    pick_entry '要关闭哪几个？输入编号，多个用逗号分隔（回车返回）: ' 1 || return 0
    printf '\n'
    for i in "${picked[@]}"; do
        entry "$i"
        if (( e_ssh )); then printf '%s 不能关闭，跳过（换 SSH 端口请到「SSH 管理」）。\n' "$e_name"; continue; fi
        targets+=("$i")
        printf '将关闭：%s\n' "$e_name"
    done
    (( ${#targets[@]} )) || return 0
    printf '关闭后外部就访问不了这些端口了。\n'
    confirm '确认关闭？' || { printf '已取消。\n'; return 0; }
    for i in "${targets[@]}"; do
        entry "$i"
        bash "$SELF" ports close "$e_port" "$e_proto" || true
    done
}
menu_ports() {
    local choice
    not_ready && return 0
    while true; do
        sub_title '端口访问管理'
        access_load
        printf '\n'; access_print 1
        [[ -z $(rule_info --other) ]] || printf '\n  %s另有不归这里管的规则，在「状态总览」里可以看到。%s\n' "$dim" "$reset"
        [[ $(ufw status) == 'Status: active'* ]] ||
            printf '\n  %s防火墙没有启用，现在所有端口都对外开放；这些规则启用后才生效。%s\n' "$c_warn" "$c_off"
        sub_actions '放行新端口' '修改某个端口允许的 IP' '端口改成所有 IP 可访问' '换成别的端口号' '关闭端口' '查看端口监听'
        menu_choose 6 || return 0
        case $choice in
            1) access_add ;;
            2) access_edit ;;
            3) access_open ;;
            4) access_move ;;
            5) access_close ;;
            6) show_listeners || true ;;
        esac
        pause
    done
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
    if (( partial )); then REPLY='● 仅指定 IP'; state_color=$c_warn
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
    local choice active ping label_fw label_ping
    not_ready && return 0
    while true; do
        sub_title '防火墙与 Ping'
        printf '\n'; firewall_row; ping_row
        active=0; [[ $(ufw status) != 'Status: active'* ]] || active=1
        ping_state; ping=$REPLY
        if (( active )); then label_fw='停用防火墙'; else label_fw='启用防火墙'; fi
        if [[ $ping == blocked ]]; then label_ping='允许 ping'; else label_ping='禁止 ping'; fi
        sub_actions "$label_fw" "$label_ping"
        menu_choose 2 || return 0
        printf '\n'
        case $choice in
            1) if (( active )); then bash "$SELF" firewall disable || true; else bash "$SELF" firewall enable || true; fi ;;
            2)
                case $ping in
                    blocked) bash "$SELF" ping on || true ;;
                    unknown) printf 'UFW 的 ping 规则被手动改过，无法自动修改。\n' ;;
                    *) bash "$SELF" ping off || true ;;
                esac ;;
        esac
        pause
    done
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
menu_ssh() {
    local choice pa label_port label_pa
    while true; do
        sub_title 'SSH 管理'
        session_auth
        ssh_status
        pa=$(sshd_value passwordauthentication) || pa=''
        if [[ -f $PENDING_FILE ]]; then label_port='完成端口迁移（待确认）'; else label_port='修改 SSH 端口'; fi
        if [[ $pa == no ]]; then label_pa='打开密码登录'; else label_pa='关闭密码登录（只用密钥）'; fi
        sub_actions "$label_port" '修改登录密码' '管理公钥' "$label_pa" '登录记录'
        menu_choose 5 || return 0
        case $choice in
            1) menu_ssh_change ;;
            2) if ask_login_user '修改哪个用户的密码？'; then bash "$SELF" passwd "$REPLY" || true; fi ;;
            3) if ask_login_user '管理哪个用户的公钥？'; then bash "$SELF" keys "$REPLY" || true; fi ;;
            4)
                printf '\n'
                if [[ $pa == no ]]; then bash "$SELF" password-login on || true
                else bash "$SELF" password-login off || true; fi ;;
            5) printf '\n'; menu_logins ;;
        esac
        pause
    done
}
menu_f2b() {
    local choice label_sync
    while true; do
        sub_title 'Fail2ban 管理'
        show_f2b
        label_sync='按 SSH 端口重新同步'
        (( ! f2b_sync )) || label_sync+="（需要同步）"
        sub_actions '解封 IP' "$label_sync"
        menu_choose 2 || return 0
        case $choice in
            1)
                if [[ -z $f2b_status ]]; then printf '\nFail2ban 没有运行。\n'
                elif [[ -z $(f2b_field 'Banned IP list') ]]; then printf '\n现在没有被封禁的 IP。\n'
                else menu_unban; fi ;;
            2)
                printf '\n'
                if confirm '按当前 SSH 端口重新同步 Fail2ban？' y; then bash "$SELF" sync || true; fi ;;
        esac
        pause
    done
}
menu() {
    local choice fw ban current raw columns menu_span wide cyan purple reset bold dim
    set_colors; menu_colors
    while true; do
        clear_screen; menu_layout
        fw='未安装' ban='未安装'
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
        menu_draw "$fw" "$ban" "$current"
        menu_choose 6 || return 0
        case $choice in
            1) bash "$SELF" install || true; pause ;;
            2) bash "$SELF" status || true; pause ;;
            3) menu_ports ;;
            4) menu_ssh ;;
            5) menu_f2b ;;
            6) menu_firewall ;;
        esac
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
trap 'printf "\n操作中断：上面这一步执行失败（脚本第 %s 行），部分配置可能已经修改。\n请保留当前 SSH 连接，用主菜单 2 查看状态后再重试。\n" "$LINENO" >&2' ERR
[[ $EUID -eq 0 ]] || die '需要 root 权限，请用 sudo vpsfw 运行。'
if [[ $mode =~ ^(install|menu|ssh|firewall|passwd|keys|password-login|ping)$ ]]; then
    [[ -t 0 ]] || die '请下载脚本后在交互终端运行，不要通过管道运行。'
fi
. /etc/os-release
supported_os || die '此脚本支持 Debian 10–14、Ubuntu 18.04–26.04、Rocky / AlmaLinux 8–10。'
[[ -d /run/systemd/system ]] || die '需要使用 systemd 的系统。'
systemctl cat ssh.service >/dev/null 2>&1 || SSH_UNIT=sshd.service
SSH_SOCKET_UNIT=${SSH_UNIT%.service}.socket
# Backups live in /var/backups, which only Debian-family systems create.
mkdir -p /var/backups

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
# A whitelisted SSH port stays whitelisted; make sure it still lets this session in before enabling.
if command -v ufw >/dev/null; then
    load_rules
    sources=$(port_sources "$ssh_port" tcp | paste -sd, -)
    [[ -z $sources ]] || check_session_allowed "$ssh_port" "$sources"
fi
printf '\n初始化将会：\n'
printf '  · 安装 UFW 和 Fail2ban\n'
if ! command -v apt-get >/dev/null; then
    printf '  · 从 EPEL 源安装软件，停用系统自带的 firewalld，改由 UFW 管理；firewalld 原来放行的端口会搬到 UFW\n'
fi
printf '  · 放行 SSH 端口 %s/TCP，拒绝其他未放行的入站连接（IPv4 和 IPv6），出站不限\n' "$ssh_port"
printf '  · SSH 登录 5 分钟内失败 5 次（包括拿真实用户名反复试密钥），封禁该 IP 10 分钟\n'
printf '  · 保留已有的 UFW 规则；备份后覆盖 /etc/fail2ban/jail.d/sshd.local\n'
printf '\n不修改 SSH 端口；其他端口初始化后在主菜单 3「端口访问管理」里放行。\n'
printf '不适合 Docker 端口映射、NAT 转发、VPN 网关或已有复杂防火墙的服务器。\n'
printf '建议先打开服务商网页控制台备用，万一连不上可以从那里恢复。\n\n'
if (( reinit )); then confirm '仍要重新初始化？' || cancel '没有修改任何配置'
else confirm '开始初始化？' || cancel '没有修改任何配置'; fi

if command -v apt-get >/dev/null; then
    if ! { apt-get update && apt-get install -y ufw fail2ban python3 python3-systemd nftables iproute2 util-linux; }; then
        # Debian 10 and 11 are out of support; their packages moved to archive.debian.org.
        [[ ${ID:-} != debian || ! ${VERSION_ID:-} =~ ^(10|11)$ ]] ||
            die "Debian ${VERSION_ID} 已停止维护，软件源搬到了 archive.debian.org，请先把 /etc/apt/sources.list 里的地址改过去。"
        die '软件安装失败，请检查网络和 /etc/apt/sources.list。'
    fi
else
    # Rocky and AlmaLinux: ufw and fail2ban come from EPEL; semanage labels new SSH ports for SELinux.
    dnf install -y epel-release
    dnf install -y ufw fail2ban-server fail2ban-systemd python3 python3-systemd nftables iproute util-linux \
        policycoreutils-python-utils
fi
# EPEL's ufw ships with ENABLED=yes but nothing loaded, so every rule change fails until it is enabled.
if [[ $(ufw status 2>/dev/null) == 'Status: inactive'* ]]; then
    sed -i 's/^ENABLED=yes/ENABLED=no/' /etc/ufw/ufw.conf
fi
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
# Two firewalls would fight over the same traffic: carry firewalld's open ports over, then switch it off.
if systemctl is-active --quiet firewalld 2>/dev/null; then
    for item in $(firewall-cmd --list-ports) \
                $(for service in $(firewall-cmd --list-services); do firewall-cmd --info-service="$service" |
                    sed -n 's/^ *ports: *//p'; done); do
        port=${item%/*} proto=${item#*/}
        [[ $proto == tcp || $proto == udp ]] && valid_spec "${port/-/:}" || continue
        [[ $proto == tcp ]] && [[ ,$all_ssh_ports,$ssh_port, == *,$port,* ]] && continue
        port_rule add "${port/-/:}" "$proto" any
        printf '已从 firewalld 搬过来：%s/%s\n' "${port/-/:}" "$proto"
    done
fi
if systemctl is-enabled --quiet firewalld 2>/dev/null || systemctl is-active --quiet firewalld 2>/dev/null; then
    systemctl disable --now --quiet firewalld
    printf '已停用 firewalld，改由 UFW 管理防火墙。\n'
fi
ufw default deny incoming
ufw default allow outgoing
ufw logging low
ufw --force enable
ufw reload
systemctl enable --quiet ufw

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
printf '  2. 网站、数据库等其他端口，在主菜单 3「端口访问管理」里放行（服务商安全组也要放行）\n\n'
printf '万一连不上：在当前窗口或服务商控制台执行 ufw disable 关闭防火墙；\n'
printf '如果是自己的 IP 被误封：fail2ban-client set sshd unbanip 你的公网IP\n'
