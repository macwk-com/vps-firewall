#!/usr/bin/env bash
# VPS Firewall — Debian 13, directly installed services.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 077

die() { printf '\n错误：%s\n' "$*" >&2; exit 1; }
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
  vpsfw firewall enable|disable

ports add/delete 端口列表 [tcp|udp|both] [来源IP/CIDR|any]
ports change 旧端口或范围 新端口或范围 [tcp|udp|both] [来源IP/CIDR|any]
默认协议 tcp，默认来源 any（所有来源）；范围格式 8000:8010。
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
parse_ports() {
    local list=$1 port existing
    [[ $list =~ ^[0-9:,]+$ && $list != *, && $list != ,* && $list != *,,* ]] || die '端口格式：443,8000:8010，不带空格。'
    local raw=()
    IFS=, read -r -a raw <<< "$list"
    ports=()
    for port in "${raw[@]}"; do
        valid_spec "$port" || die "端口或范围无效：$port"
        [[ ${port%%:*} != "${port##*:}" ]] || port=${port%%:*}
        local duplicate=0
        for existing in ${ports[@]+"${ports[@]}"}; do [[ $port != "$existing" ]] || duplicate=1; done
        (( duplicate )) || ports+=("$port")
    done
}
normalize_source() {
    python3 - "$1" <<'PYSOURCE'
import ipaddress,sys
s=sys.argv[1]
if s=='any': print(s)
else:
    try:
        n=ipaddress.ip_network(s,strict=True)
        # Explicit /0 stays address-family-specific, unlike 'any'.
        print(str(n.network_address) if n.prefixlen==n.max_prefixlen else str(n))
    except ValueError: raise SystemExit('来源必须是 IP 或正确对齐的 CIDR 网段，例如 192.0.2.0/24')
PYSOURCE
}
load_rules() { rules=$(ufw show added); }
# Parse only simple inbound allow rules. No eval or execution of rule text.
rule_info() {
    printf '%s\n' "$rules" | python3 -c '
import shlex,sys,ipaddress
port,proto,source=sys.argv[1:]
def norm(s):
    if s=="any": return s
    n=ipaddress.ip_network(s,strict=False)
    return str(n.network_address) if n.prefixlen==n.max_prefixlen else str(n)
matches=[]
for line in sys.stdin:
    try:
        t=shlex.split(line)
        if t[:2]!=["ufw","allow"]: continue
        t=t[2:]; comment=""
        if "comment" in t:
            i=t.index("comment")
            if len(t)!=i+2: continue
            comment=t[i+1]; t=t[:i]
        if t[:1]==["in"]: t=t[1:]
        if len(t)==1 and "/" in t[0]:
            rp,rproto=t[0].split("/",1); src="any"
        else:
            fields={}; i=0
            while i<len(t):
                if t[i] not in ("proto","from","to","port") or t[i] in fields or i+1>=len(t): break
                fields[t[i]]=t[i+1]; i+=2
            if i!=len(t) or fields.get("to","any")!="any": continue
            if "port" not in fields or "proto" not in fields: continue
            # Do not confuse a source port with a destination port.
            if "to" not in t or t.index("port")<t.index("to"): continue
            rp=fields["port"]; rproto=fields["proto"]; src=fields.get("from","any")
        if (rp,rproto,norm(src))==(port,proto,source): matches.append(comment)
    except ValueError: continue
if len(matches)>1:
    print("精确匹配规则不唯一，请先用 ufw show added 检查",file=sys.stderr); sys.exit(2)
if not matches: sys.exit(1)
print(matches[0])
' "$1" "$2" "${3:-any}"
}
existing_rule() {
    rule_info "$1" "$2" "${3:-any}" >/dev/null
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
            die "端口范围 $spec 包含 SSH 端口 $p，请使用 SSH 专用管理。"
        fi
    done
    listeners=$(ss -H -lntp "sport >= :$first and sport <= :$last") || die '无法检查实际监听端口。'
    [[ $listeners != *'"sshd"'* && $listeners != *'"sshd-session"'* ]] || die "端口 $spec 正由 SSH 使用。"
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
    ufw "${args[@]}"
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
        command -v "$cmd" >/dev/null || die '请先选择菜单 1，初始化 UFW 和 Fail2ban。'
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
    fail2ban-client -t
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
    [[ $actual == "$expected" ]] || die "SSH 生效配置端口异常：$actual；期望：$expected"
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
        ufw insert 1 allow "$p/tcp" comment 'SSH'
    done
    ssh_config_files edit "$backup_dir" "$target_ports"
    sshd -t
    write_f2b "$target_ports"
    systemctl reload ssh.service
    verify_ssh_ports "$target_ports"
    systemctl enable fail2ban
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
ssh_change() {
    local new=$1 old combined comment lookup_status
    valid_port "$new" || die '请输入 1 到 65535 的端口。'
    ssh_preflight
    old=$(ssh_ports)
    [[ ,$old, != *,$new,* ]] || die '该端口已经是 SSH 监听端口。'
    [[ -z $(ss -H -lnt "sport = :$new") ]] || die '新 TCP 端口已被其他程序使用。'
    load_rules
    if comment=$(rule_info "$new" tcp); then
        [[ $comment == SSH ]] || die '新端口已有普通 TCP 放行规则，请先确认用途并删除该规则。'
    else
        lookup_status=$?
        (( lookup_status == 1 )) || die '新端口规则不明确，请先检查。'
    fi
    printf 'SSH：%s → %s；先保留新旧两个入口。\n' "$old" "$new"
    printf '请在服务商安全组放行 %s/TCP，保留当前窗口。\n' "$new"
    read -r -p '开始迁移？输入 yes: ' answer
    [[ $answer == yes ]] || die '已取消。'
    ssh_snapshot
    start_transaction
    combined=$(printf '%s,%s\n' "$old" "$new" | tr ',' '\n' | sort -nu | paste -sd, -)
    apply_ssh_ports "$combined"
    mkdir -p "$STATE_DIR"
    printf '%s\n%s\n%s\n' "$backup_dir" "$old" "$new" > "$PENDING_FILE.tmp"
    mv "$PENDING_FILE.tmp" "$PENDING_FILE"
    end_transaction
    prune_backups
    printf '\n新端口 %s 已监听；旧入口 %s 保留，Fail2ban 同时保护两者。\n' "$new" "$old"
    printf '请新开终端用新端口登录，然后在新会话运行本脚本，选择「确认迁移」。\n'
}
ssh_finish() {
    read_pending
    [[ ${session_port:-} == "$pending_new" ]] || die "必须在通过 $pending_new 新建的 SSH 会话中确认；当前会话不会关闭旧入口。"
    ssh_preflight pending
    printf '当前会话使用新端口 %s，将关闭旧监听 %s。\n' "$pending_new" "$pending_old"
    read -r -p '确认完成迁移？输入 yes: ' answer
    [[ $answer == yes ]] || die '已取消，继续保留双端口。'
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
            ufw --force delete allow "$p/tcp" comment 'SSH'
        fi
    done
    prune_backups
    printf '迁移完成：SSH 和 Fail2ban 使用 %s；旧 SSH 监听已关闭。\n' "$pending_new"
    printf '其他未标记的旧 UFW 放行规则不会删除，可在规则列表中检查。\n'
}
ssh_rollback() {
    read_pending
    printf '将恢复迁移前 SSH 端口 %s；保留新增的 UFW 放行规则以便排查。\n' "$pending_old"
    read -r -p '确认回退？输入 yes: ' answer
    [[ $answer == yes ]] || die '已取消。'
    restore_ssh_backup "$pending_backup"
    rm -f "$PENDING_FILE"
    backup_dir=$pending_backup
    prune_backups
    printf '已恢复迁移前的 SSH 和 Fail2ban 配置。\n'
}
show_status() {
    printf '\n── UFW ──\n'
    if command -v ufw >/dev/null; then
        ufw status verbose
        printf '\n── 已保存 UFW 规则 ──\n'
        ufw show added
    else printf '未安装\n'; fi
    printf '\n── SSH 实际配置端口 ──\n'
    ssh_ports || true
    printf '\n── Fail2ban SSH ──\n'
    if command -v fail2ban-client >/dev/null; then fail2ban-client status sshd || true; else printf '未安装\n'; fi
    if [[ -f $PENDING_FILE ]]; then
        printf '\n有待确认的 SSH 迁移；请通过新端口登录后选择「确认迁移」。\n'
    fi
}
ports_command() {
    local op=${1:-list} list=${2:-} proto source new='' p protocol comment
    command -v ufw >/dev/null || die '请先初始化 UFW。'
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
            new=$3; proto=${4:-tcp}; source=${5:-any}
            valid_spec "$list" && valid_spec "$new" || die '替换操作每次接受一个端口或范围。'
            [[ ${new%%:*} != "${new##*:}" ]] || new=${new%%:*}
            [[ ${list%%:*} != "${list##*:}" ]] || list=${list%%:*}
            [[ $list != "$new" ]] || die '新旧端口相同。' ;;
        *) die 'ports 支持 list、add、delete、change。' ;;
    esac
    [[ $proto == tcp || $proto == udp || $proto == both ]] || die '协议为 tcp、udp 或 both。'
    source=$(normalize_source "$source") || die '来源地址无效。'
    parse_ports "$list"
    local protocols=(tcp udp)
    [[ $proto == both ]] || protocols=("$proto")
    # Validate the entire batch before the first mutation.
    for p in "${ports[@]}"; do
        for protocol in "${protocols[@]}"; do
            check_ssh_collision "$p" "$protocol"
            if comment=$(rule_info "$p" "$protocol" "$source"); then
                [[ $comment != *SSH* && $comment != *ssh* ]] || die 'SSH 标记的规则请通过 SSH 专用管理。'
            else
                local lookup_status=$?
                (( lookup_status == 1 )) || die '无法明确识别现有规则。'
                [[ $op == add ]] || die "$p/$protocol 来源 $source 没有精确匹配的普通放行规则。"
            fi
            if [[ $op == change ]]; then
                check_ssh_collision "$new" "$protocol"
                if comment=$(rule_info "$new" "$protocol" "$source"); then
                    [[ $comment != *SSH* && $comment != *ssh* ]] || die '新端口规则标记为 SSH。'
                else
                    local lookup_status=$?
                    (( lookup_status == 1 )) || die '无法明确识别新端口规则。'
                fi
            fi
        done
    done
    printf '操作：%s；端口：%s；新端口：%s；协议：%s；来源：%s\n' "$op" "$list" "${new:--}" "$proto" "$source"
    backup_ufw
    # Complete all additions before any deletions during a replacement.
    if [[ $op == change ]]; then
        for protocol in "${protocols[@]}"; do
            if ! existing_rule "$new" "$protocol" "$source"; then port_rule add "$new" "$protocol" "$source"; fi
        done
    fi
    for p in "${ports[@]}"; do
        for protocol in "${protocols[@]}"; do
            case "$op" in
                add) if ! existing_rule "$p" "$protocol" "$source"; then port_rule add "$p" "$protocol" "$source"; fi ;;
                delete|change) port_rule delete "$p" "$protocol" "$source" ;;
            esac
        done
    done
    load_rules
    list_ports
    prune_backups
    printf '仅修改服务器入站放行规则。已有宽泛规则可能仍允许同一端口；来源限制不会自动撤销其他放行。\n'
}
ufw_switch() {
    command -v ufw >/dev/null || die '请先初始化。'
    if [[ $1 == enable ]]; then
        local p current
        current=$(ssh_ports)
        [[ -n $current ]] || die '无法识别 SSH 端口，拒绝启用。'
        IFS=, read -r -a current_ports <<< "$current"
        for p in "${current_ports[@]}"; do ufw insert 1 allow "$p/tcp" comment 'SSH'; done
        if [[ -n ${session_port:-} ]]; then ufw insert 1 allow "$session_port/tcp" comment 'SSH'; fi
        ufw enable
    else
        read -r -p '停用 UFW 会撤销其防护。确认？输入 yes: ' answer
        [[ $answer == yes ]] || die '已取消。'
        ufw disable
    fi
}
# Menu labels use ASCII and three-byte CJK characters. Count terminal cells,
# not UTF-8 bytes, so Chinese labels and two-digit numbers stay aligned.
menu_width() {
    local text=$1 ascii
    ascii=${text//[! -~]/}
    REPLY=$(( ${#ascii} + (${#text} - ${#ascii}) / 3 * 2 ))
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
    printf '\n  %sV P S F W%s\n' "$cyan$bold" "$reset"
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
                  '防火墙开关' '修改 SSH 端口' '确认 SSH 迁移' '回退 SSH 迁移' 'Fail2ban 管理' '查看配置备份')
    if (( wide )); then
        menu_pair '端口管理' '防护与 SSH'
        printf '\n'
        for ((i=0;i<6;i++)); do
            left=${labels[i]}; right=${labels[i+6]}
            menu_width "$left"; padding=$((28 - 4 - REPLY))
            menu_item "$((i+1))" "$left"
            printf '%*s    ' "$padding" ''
            # The first column already supplied the row indentation.
            printf '%s%2s.%s %s\n' "$cyan" "$((i+7))" "$reset" "$right"
        done
    else
        printf '  %s端口管理%s\n\n' "$dim" "$reset"
        for ((i=0;i<12;i++)); do
            if (( i == 6 )); then printf '\n  %s防护与 SSH%s\n\n' "$dim" "$reset"; fi
            menu_item "$((i+1))" "${labels[i]}"; printf '\n'
        done
    fi
    printf '\n'; menu_rule
    menu_item 0 '退出'; printf '\n'; menu_rule
    if [[ -f $PENDING_FILE ]]; then
        printf '\n  %sSSH 迁移待确认%s\n  请从新端口登录，再选择 9。\n' "$cyan" "$reset"
    fi
    printf '\n'
}
menu() {
    local choice values proto old new reply rc source columns
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
        read -r -p '  请选择 [0-12]: ' choice || return 0
        rc=0
        case "$choice" in
            0) return 0 ;;
            1) bash "$SELF" install || rc=$? ;;
            2) bash "$SELF" status || rc=$? ;;
            3|4)
                read -r -p '端口（443,8000:8010）: ' values
                read -r -p '协议 tcp / udp / both [tcp]: ' proto
                read -r -p '来源 IP / CIDR [any 所有来源]: ' source
                if [[ $choice == 3 ]]; then reply=add; else reply=delete; fi
                printf '即将 %s：%s / %s，来源 %s\n' "$reply" "$values" "${proto:-tcp}" "${source:-any}"
                read -r -p '确认？输入 yes: ' answer
                if [[ $answer == yes ]]; then bash "$SELF" ports "$reply" "$values" "${proto:-tcp}" "${source:-any}" || rc=$?; fi ;;
            5)
                read -r -p '旧端口或范围: ' old
                read -r -p '新端口或范围: ' new
                read -r -p '协议 tcp / udp / both [tcp]: ' proto
                read -r -p '来源 IP / CIDR [any 所有来源]: ' source
                printf '%s → %s / %s，来源 %s\n' "$old" "$new" "${proto:-tcp}" "${source:-any}"
                read -r -p '确认替换？输入 yes: ' answer
                if [[ $answer == yes ]]; then bash "$SELF" ports change "$old" "$new" "${proto:-tcp}" "${source:-any}" || rc=$?; fi ;;
            6) ss -lntup || rc=$? ;;
            7)
                read -r -p '输入 enable 启用，disable 停用: ' reply
                bash "$SELF" firewall "$reply" || rc=$? ;;
            8)
                read -r -p '新的 SSH 端口: ' new
                bash "$SELF" ssh change "$new" || rc=$? ;;
            9) bash "$SELF" ssh finish || rc=$? ;;
            10) bash "$SELF" ssh rollback || rc=$? ;;
            11)
                if command -v fail2ban-client >/dev/null; then fail2ban-client status sshd || true; fi
                read -r -p '是否按 SSH 当前配置同步 Fail2ban？输入 yes: ' reply
                if [[ $reply == yes ]]; then bash "$SELF" sync || rc=$?; fi ;;
            12) find /var/backups -maxdepth 1 -type d -name 'vps-security*' -print ;;
            *) printf '请选择菜单中的数字。\n' ;;
        esac
        (( rc == 0 )) || printf '\n本次操作未完成（退出码 %s），请查看上面的提示。\n' "$rc"
        read -r -p '按回车返回菜单……' reply || return 0
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
    status|ssh|ports|firewall|sync)
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
trap 'printf "\n操作失败（第 %s 行）。请保留当前 SSH 连接；脚本可能已完成部分配置。\n" "$LINENO" >&2' ERR
[[ $EUID -eq 0 ]] || die '请以 root 执行，或使用 sudo bash 运行。'
if [[ $mode == install || $mode == menu || $mode == ssh || $mode == firewall ]]; then
    [[ -t 0 ]] || die '请下载脚本后在交互终端运行，不要通过管道运行。'
fi
. /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] || die '此脚本针对 Debian 13。'
[[ -d /run/systemd/system ]] || die '需要使用 systemd 的系统。'

session_port=''
if [[ -n ${SSH_CONNECTION:-} ]]; then
    read -r _ _ _ session_port <<< "$SSH_CONNECTION"
    valid_port "$session_port" || die '无法正确解析当前 SSH 端口。'
fi
if [[ $mode != menu && $mode != status ]]; then
    # Serialize writes across separate SSH windows.
    exec 9>/run/lock/vps-security.lock
    flock -n 9 || die '另一个管理操作正在运行，请稍后重试。'
fi
case "$mode" in
    menu) menu; exit 0 ;;
    status) show_status; exit 0 ;;
    ports) ports_command "${dispatch_args[@]}"; exit 0 ;;
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
        systemctl enable fail2ban
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
default_ssh=$session_port
printf '适用范围：Debian 13，服务器宿主机的入站端口与 SSH 防护。\n'
printf '不适用于 Docker 端口映射、NAT 转发、VPN 网关或已有复杂防火墙的服务器。\n'
printf '保留已有 UFW 规则；备份后覆盖 /etc/fail2ban/jail.d/sshd.local。\n'
printf '初始化不修改监听端口；SSH 端口迁移请使用菜单 8，其他端口通过菜单 3 添加。\n\n'
if [[ -z $ssh_port ]]; then
    read -r -p "实际 SSH 端口 [${default_ssh:-必须填写}]: " ssh_port
    ssh_port=${ssh_port:-$default_ssh}
fi
valid_port "$ssh_port" || die 'SSH 端口必须是 1 到 65535 的整数。'
if [[ -n $session_port && $ssh_port != "$session_port" ]]; then
    die "当前 SSH 连接使用 $session_port，请填写这个实际端口；修改 SSH 端口须另行操作。"
fi
printf '\n初始化只放行 SSH 入口（当前 %s/TCP），保留已有规则。\n' "$ssh_port"
printf '默认拒绝其他未放行入站，允许出站，同时启用 IPv6 防护。\n'
printf 'SSH：5 分钟内失败 5 次，封禁 SSH 端口 10 分钟。\n'
printf '请确认 SSH 端口正确，且已准备好服务商网页控制台作为恢复入口。\n'
read -r -p '确认适用上述场景并开始？输入 yes: ' answer
[[ $answer == yes ]] || die '已取消，尚未修改配置。'

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
ufw insert 1 allow "$ssh_port/tcp" comment 'SSH'
IFS=, read -r -a all_ssh_array <<< "$all_ssh_ports"
for p in "${all_ssh_array[@]}"; do ufw insert 1 allow "$p/tcp" comment 'SSH'; done
if grep -q '^IPV6=' /etc/default/ufw; then
    sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
else
    printf '\nIPV6=yes\n' >> /etc/default/ufw
fi
# Add again after enabling IPv6 so both address families have the SSH rule.
ufw insert 1 allow "$ssh_port/tcp" comment 'SSH'
for p in "${all_ssh_array[@]}"; do ufw insert 1 allow "$p/tcp" comment 'SSH'; done
ufw default deny incoming
ufw default allow outgoing
ufw logging low
ufw --force enable
ufw reload

systemctl enable fail2ban
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

printf '\n===== UFW 状态 =====\n'
ufw status verbose
printf '\n===== Fail2ban SSH 状态 =====\n'
fail2ban-client status sshd
printf '\n===== 实际启用的封禁动作 =====\n'
fail2ban-client get sshd actions
prune_backups
printf '\n配置完成。备份：%s\n' "$backup_dir"
printf '请保留当前窗口，新开 SSH 连接测试登录。\n'
printf '其他服务端口通过菜单 3 添加；服务商安全组需同步放行。\n'
printf '旧的 UFW 放行规则会保留。更换端口后请检查：ufw status numbered\n'
printf '恢复访问：在原会话或服务商控制台执行 ufw disable\n'
printf '如被 Fail2ban 误封：fail2ban-client set sshd unbanip 你的公网IP\n'
