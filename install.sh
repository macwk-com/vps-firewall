#!/usr/bin/env bash
# VPS Firewall installer — https://github.com/macwk-com/vps-firewall
set -Eeuo pipefail
umask 077

fail() { printf '\n安装失败：%s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail '请以 root 运行安装命令。'
. /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] || fail '目前支持 Debian 13。'
command -v curl >/dev/null || fail '请先安装 curl 和 ca-certificates。'

source_url='https://raw.githubusercontent.com/macwk-com/vps-firewall/main/vpsfw.sh'
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

printf '正在下载 VPS Firewall……\n'
curl --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 \
    --retry 2 -fSL "$source_url" -o "$download" || fail '下载失败，请确认仓库公开、main 分支存在且 vpsfw.sh 位于根目录。'
[[ -s $download ]] || fail '下载结果为空。'
grep -Fq '# VPS Firewall —' "$download" || fail '下载内容不是预期的 VPS Firewall 脚本。'
bash -n "$download" || fail '下载的脚本没有通过 Bash 语法检查。'
chmod 755 "$download"
mv -f "$download" "$destination"
trap - EXIT INT TERM

printf '\n安装完成。以后输入 vpsfw 即可打开菜单。\n'
if [[ -t 0 && -t 1 ]]; then
    exec "$destination"
fi
