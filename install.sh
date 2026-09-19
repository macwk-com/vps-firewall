#!/usr/bin/env bash
# VPS Firewall installer — https://github.com/macwk-com/vps-firewall
set -Eeuo pipefail
umask 077

fail() { printf '\n安装失败：%s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail '请以 root 运行安装命令。'
. /etc/os-release
case ${ID:-} in
    debian) [[ ${VERSION_ID:-} =~ ^(10|11|12|13|14)$ || ${VERSION_CODENAME:-} == forky ]] ;;
    ubuntu) [[ ${VERSION_ID:-} =~ ^(18|20|22|24|26)\.04$ ]] ;;
    rocky|almalinux) [[ ${VERSION_ID%%.*} =~ ^(8|9|10)$ ]] ;;
    *) false ;;
esac || fail '目前支持 Debian 10–14、Ubuntu 18.04–26.04、Rocky / AlmaLinux 8–10。'
command -v curl >/dev/null || fail '请先安装 curl 和 ca-certificates。'

repo='macwk-com/vps-firewall'
install_dir=/usr/local/bin
destination=$install_dir/vpsfw
mkdir -p "$install_dir"
[[ ! -L $destination ]] || fail "$destination 是已有软链接，请先人工检查。"
if [[ -e $destination ]]; then
    [[ -f $destination ]] || fail "$destination 不是普通文件。"
    grep -Fq '# VPS Firewall —' "$destination" || fail "$destination 已被其他程序占用，不会覆盖。"
fi

download=$(mktemp "$install_dir/.vpsfw-download.XXXXXXXX")
cleanup() { rm -f "$download"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# raw.githubusercontent.com caches main for 5 minutes; download by commit so a fresh push is picked up.
# The API answer is cached for at most 60 seconds. Fall back to main if it is unreachable or rate limited.
commit=$(curl --proto '=https' --connect-timeout 10 --max-time 20 -fsS \
    -H 'Accept: application/vnd.github.sha' "https://api.github.com/repos/$repo/commits/main" 2>/dev/null) || commit=''
if [[ $commit =~ ^[0-9a-f]{40}$ ]]; then
    ref=$commit
    printf '正在下载 VPS Firewall（最新提交 %s）……\n' "${commit:0:7}"
else
    ref=main
    printf '正在下载 VPS Firewall……\n'
    printf '（暂时查不到最新提交，改用 main 分支地址；刚推送的更新可能要等 5 分钟才能下载到。）\n'
fi
source_url="https://raw.githubusercontent.com/$repo/$ref/vpsfw.sh"
curl --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 \
    --retry 2 -fsSL "$source_url" -o "$download" || fail '下载失败，请确认仓库公开、main 分支存在且 vpsfw.sh 位于根目录。'
[[ -s $download ]] || fail '下载结果为空。'
grep -Fq '# VPS Firewall —' "$download" || fail '下载内容不是预期的 VPS Firewall 脚本。'
bash -n "$download" || fail '下载的脚本没有通过 Bash 语法检查。'
chmod 755 "$download"
mv -f "$download" "$destination"
trap - EXIT INT TERM

# sudo on RHEL-family systems only searches /usr/sbin and /usr/bin, so `sudo vpsfw` needs a link there.
sudo_path=$(sudo -V 2>/dev/null | sed -n 's/^Value to override user.s \$PATH with: //p' || true)
if [[ -n $sudo_path && :$sudo_path: != *:$install_dir:* ]]; then
    link=/usr/bin/vpsfw
    if [[ ! -e $link || ( -L $link && $(readlink -f "$link") == "$destination" ) ]]; then
        ln -sfn "$destination" "$link"
    else
        printf '注意：%s 已被其他程序占用，普通用户请用 sudo %s 运行。\n' "$link" "$destination"
    fi
fi

printf '\n安装完成。以后输入 vpsfw 即可打开菜单。\n'
if [[ -t 0 && -t 1 ]]; then
    exec "$destination"
fi
