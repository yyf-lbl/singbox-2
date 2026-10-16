#!/usr/bin/env bash
# ==============================================================================
#  SERV00 | SING-BOX 一键脚本（重构版，面向 FreeBSD / Serv00）
#  - 菜单与交互流程与原版保持一致
#  - 修复：进程误杀、拼写错误、端口分配逻辑、list.txt 混入颜色码等
#  - 安全：TUIC 随机密码、目录权限 700、去掉 eval、下载校验、危险操作二次确认
# ==============================================================================

if [ -z "${BASH_VERSION:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "需要 bash 4+ 运行本脚本（例如: bash $0）" >&2
    exit 1
fi

trap 'printf "\n"; exit 130' INT

# ------------------------------------------------------------------------------
# 颜色与输出（全部集中在这里，其余地方只调用函数）
# ------------------------------------------------------------------------------
C_0=$'\033[0m'
C_R=$'\033[1;3;31m'
C_G=$'\033[1;3;32m'
C_Y=$'\033[1;3;33m'
C_P=$'\033[1;3;35m'
C_C=$'\033[1;3;36m'
C_O=$'\033[1;3;38;5;208m'

_say()   { printf '%s%s%s\n' "$1" "$2" "$C_0"; }
red()    { _say "$C_R" "$*"; }
green()  { _say "$C_G" "$*"; }
yellow() { _say "$C_Y" "$*"; }
purple() { _say "$C_P" "$*"; }
cyan()   { _say "$C_C" "$*"; }
orange() { _say "$C_O" "$*"; }

# ask 变量名 "提示" [默认值]   —— 不使用 eval
ask() {
    local _ans
    printf '%s%s%s' "$C_Y" "$2" "$C_0"
    IFS= read -r _ans || { echo; exit 1; }
    [[ -z $_ans ]] && _ans=${3:-}
    printf -v "$1" '%s' "$_ans"
}

pause() {
    printf '%s操作完成，按任意键继续...%s' "$C_Y" "$C_0"
    read -rsn1 _
    echo
}

# ------------------------------------------------------------------------------
# 全局变量
# ------------------------------------------------------------------------------
WORKDIR="$HOME/sbox"
base_dir="$HOME/.beifile"
USERNAME=$(whoami)
UID_NUM=$(id -u)
FQDN=$(hostname -f 2>/dev/null || hostname)
SUBDOMAIN=${FQDN%%.*}
SERV_DOMAIN="$USERNAME.serv00.net"

API_URL="https://2670819.xyz/api.php"
GH_BASE="https://github.com/yyfalbl/singbox-2/releases/download/v1.0.0"
IPV4_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'

export CFIP=${CFIP:-'www.visa.com.tw'}
export CFPORT=${CFPORT:-'443'}
export NEZHA_SERVER=${NEZHA_SERVER:-''}
export NEZHA_PORT=${NEZHA_PORT:-'5555'}
export NEZHA_KEY=${NEZHA_KEY:-''}

# WARP（WireGuard）出站参数：默认沿用原脚本值，建议换成你自己的并通过环境变量传入
WG_PRIVATE_KEY=${WG_PRIVATE_KEY:-'oILCcN/OtgJoC2krgFM8QG212bH/cwcGOyz5JkTTFkA='}
WG_PEER_PUBLIC_KEY=${WG_PEER_PUBLIC_KEY:-'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo='}
WG_ADDR_V4=${WG_ADDR_V4:-'172.16.0.2/32'}
WG_ADDR_V6=${WG_ADDR_V6:-'2606:4700:110:8006:eeb0:dcde:fb07:fa8a/128'}
WG_RESERVED=${WG_RESERVED:-'28, 63, 66'}

# 下载文件 sha256 校验（可选）。键为下载文件名，例如 EXPECTED_SHA256[amd64-web]="xxxx"
# 为空则跳过校验，但会打印实际 hash 方便你记录。
declare -A EXPECTED_SHA256=()

mkdir -p "$base_dir" "$WORKDIR"
chmod 700 "$base_dir" "$WORKDIR" 2>/dev/null

ip_file_cache="$base_dir/unblock_ips.txt"
ARGO_CONF="$base_dir/argo.conf"
SERVER_INFO_CACHE=""
FINAL_IP=""
REALITY_PUB=""
ARGO_CONFIGURED=false
INSTALL_VLESS=false; INSTALL_VMESS=false; INSTALL_HYSTERIA2=false; INSTALL_TUIC=false
vless_port=""; vmess_port=""; hy2_port=""; tuic_port=""; socks5_port=""
declare -A PORT_MAP=()

# UUID 持久化
UUID_FILE="$base_dir/.singbox_uuid"
if [[ -s $UUID_FILE ]]; then
    UUID=$(<"$UUID_FILE")
else
    UUID=$(uuidgen)
    printf '%s\n' "$UUID" > "$UUID_FILE"
fi
export UUID

rand_str() { LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | head -c "${1:-10}"; }

# TUIC 密码持久化（不再硬编码 admin123）
TUIC_PASS_FILE="$base_dir/.tuic_pass"
if [[ -s $TUIC_PASS_FILE ]]; then
    TUIC_PASS=$(<"$TUIC_PASS_FILE")
else
    TUIC_PASS=$(rand_str 16)
    ( umask 077; printf '%s\n' "$TUIC_PASS" > "$TUIC_PASS_FILE" )
fi

# Argo 配置持久化（重启后固定隧道不丢失）
if [[ -z ${ARGO_AUTH:-} && -f $ARGO_CONF ]]; then
    # shellcheck disable=SC1090
    . "$ARGO_CONF"
fi
ARGO_DOMAIN=${ARGO_DOMAIN:-}
ARGO_AUTH=${ARGO_AUTH:-}

save_argo_conf() {
    ( umask 077; printf 'ARGO_DOMAIN=%q\nARGO_AUTH=%q\n' "$ARGO_DOMAIN" "$ARGO_AUTH" > "$ARGO_CONF" )
}

# ------------------------------------------------------------------------------
# 通用工具
# ------------------------------------------------------------------------------
b64() {
    if command -v base64 >/dev/null 2>&1; then base64 | tr -d '\n'; else openssl base64 -A; fi
}

# 从 JSON 文本里取字符串字段（不依赖 jq）
_json_get() {
    printf '%s' "$1" | tr -d '\n' |
        sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

# 进程管理：按完整路径匹配，避免误杀
proc_pids()    { pgrep -u "$UID_NUM" -f "$WORKDIR/$1( |\$)" 2>/dev/null; }
proc_running() { [[ -n $(proc_pids "$1") ]]; }

stop_proc() {
    local pids i
    pids=$(proc_pids "$1")
    [[ -z $pids ]] && return 1
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null
    for i in 1 2 3 4 5; do
        sleep 1
        [[ -z $(proc_pids "$1") ]] && return 0
    done
    # shellcheck disable=SC2046
    kill -9 $(proc_pids "$1") 2>/dev/null
    return 0
}

# 杀掉当前用户除自身及其父进程链以外的所有进程
kill_user_procs_except_self() {
    local sig=${1:-TERM} keep=" $$ " p=$$ pp pid
    while :; do
        pp=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
        [[ -z $pp || $pp -le 1 ]] && break
        keep+="$pp "
        p=$pp
    done
    for pid in $(pgrep -u "$UID_NUM"); do
        [[ $keep == *" $pid "* ]] && continue
        kill -"$sig" "$pid" 2>/dev/null
    done
}

config_has_vmess() {
    [[ -f $WORKDIR/config.json ]] &&
        grep -qE '"type"[[:space:]]*:[[:space:]]*"vmess"' "$WORKDIR/config.json"
}

config_vmess_port() {
    [[ -f $WORKDIR/config.json ]] || return
    awk '/"type"[[:space:]]*:[[:space:]]*"vmess"/ {f=1}
         f && /"listen_port"/ {gsub(/[^0-9]/, ""); print; exit}' "$WORKDIR/config.json"
}

# ------------------------------------------------------------------------------
# IP 检测
# ------------------------------------------------------------------------------
# 输出可用(未被墙)IP，每行一个。参数 cache: 允许使用 60 分钟内的缓存
fetch_unblock_ips() {
    if [[ ${1:-} == cache && -s $ip_file_cache ]] &&
       [[ -n $(find "$ip_file_cache" -mmin -60 2>/dev/null) ]]; then
        cat "$ip_file_cache"
        return 0
    fi

    local hn num host resp ip st out=()
    hn=$(hostname)
    num=${hn%%.*}; num=${num#s}
    for host in "$hn" "web${num}.serv00.com" "cache${num}.serv00.com"; do
        resp=$(curl -sk --fail --max-time 8 "$API_URL?host=$host") || continue
        [[ -z $resp ]] && continue
        ip=$(_json_get "$resp" host)
        st=$(_json_get "$resp" status)
        [[ $st == Accessible && $ip =~ $IPV4_RE ]] && out+=("$ip")
    done
    (( ${#out[@]} )) || return 1
    printf '%s\n' "${out[@]}" | tee "$ip_file_cache"
}

beiyong_ip() {
    local saved ips
    if [[ -s $base_dir/.serv00_ip ]]; then
        saved=$(<"$base_dir/.serv00_ip")
        green "当前服务器备用 IP 地址: $saved"
        return
    fi
    ips=$(netstat -i 2>/dev/null | awk '/^ixl.*mail[0-9]+/ {print $3}' | cut -d '/' -f 1)
    if [[ -z $ips ]]; then
        red "未能自动获取备用 IP。"
    else
        printf '%s\n' "$ips" > "$base_dir/.serv00_ip"
        green "当前服务器备用 IP 地址: $ips"
    fi
}

server_info_raw() {
    local ip ips i
    ip=$(curl -s --max-time 5 https://api.ipify.org)
    [[ -z $ip ]] && ip=$(curl -s --max-time 5 ipv6.ip.sb)
    green "当前服务器的 IP 地址是：$ip"
    if [[ $FQDN == *.serv00.com ]]; then
        green "当前服务器主机地址是：$FQDN"
        yellow "本机域名是: $SERV_DOMAIN"
        mapfile -t ips < <(fetch_unblock_ips cache)
        if (( ${#ips[@]} )); then
            for i in "${ips[@]}"; do green "当前服务器可用 ip 地址: $i"; done
        else
            echo "没有找到任何可用的未被墙服务器IP (通过 2670819.xyz 查询)。"
            cyan "未能获取 API IP，尝试获取本地备用 IP..."
            beiyong_ip
        fi
    else
        cyan "当前环境非 Serv00 标准节点，请检查。"
    fi
}

get_server_info() {
    [[ -z $SERVER_INFO_CACHE ]] && SERVER_INFO_CACHE=$(server_info_raw)
    printf '%s\n' "$SERVER_INFO_CACHE"
}

# 选择/检测 IP，结果放到 FINAL_IP
get_ip() {
    local ips=() ip="" choice i
    yellow "正在自动检测所有可用的IP地址... (这可能需要几秒钟)"
    mapfile -t ips < <(fetch_unblock_ips)

    if (( ${#ips[@]} )); then
        green "检测到以下可用IP地址："
        i=1
        for ip in "${ips[@]}"; do green "  [$i] $ip"; i=$((i + 1)); done
        echo
        while true; do
            ask choice "请选择一个IP (输入编号, 或直接按Enter随机选择, 或手动输入其他IP): "
            if [[ -z $choice ]]; then
                ip=${ips[RANDOM % ${#ips[@]}]}
                green "已为您随机选择IP: $ip"; break
            elif [[ $choice =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#ips[@]} )); then
                ip=${ips[choice-1]}
                green "您已选择IP: $ip"; break
            elif [[ $choice =~ ^[A-Za-z0-9.:\[\]-]+$ ]]; then
                ip=$choice
                green "您已手动输入IP/域名: $ip"; break
            else
                red "输入无效，请重新输入。"
            fi
        done
    else
        yellow "API未能找到未被墙的IP，将尝试其他备用方案..."
        ip=$(netstat -i 2>/dev/null | awk '/^ixl.*mail[0-9]+/ {print $3}' | cut -d '/' -f 1 | head -n 1)
        if [[ -z $ip ]]; then
            echo "  -> 未找到netstat备用IP，正在获取服务器主IP..." >&2
            ip=$(curl -s --max-time 5 https://api.ipify.org)
            if [[ -z $ip ]]; then
                local v6
                v6=$(curl -s --max-time 5 ipv6.ip.sb)
                [[ -n $v6 ]] && ip="[$v6]"
            fi
        fi
        if [[ -n $ip ]]; then
            green "已自动选择备用IP: $ip"
        else
            red "致命错误：所有方法都无法获取IP地址！"
            return 1
        fi
    fi
    FINAL_IP=$ip
    yellow "最终使用的IP地址是: ${FINAL_IP}"
    sleep 1
}

# ------------------------------------------------------------------------------
# 端口管理（devil）
# ------------------------------------------------------------------------------
port_in_use() {
    sockstat -46 2>/dev/null | awk -v p="$1" '{n=split($6, a, ":"); if (n > 0 && a[n] == p) f=1} END {exit !f}'
}

load_ports() {
    local out port typ desc
    PORT_MAP=()
    out=$(devil port list 2>/dev/null) || return 1
    while read -r port typ desc; do
        [[ $port =~ ^[0-9]+$ ]] || continue
        PORT_MAP["$typ|$desc"]=$port
    done <<< "$out"
}

count_ports() {
    devil port list 2>/dev/null | awk '$1 ~ /^[0-9]+$/' | wc -l | tr -d ' '
}

delete_unused_port() {
    local list port typ desc choice
    list=$(devil port list 2>/dev/null | awk 'NR>1 && NF')
    if [[ -z $list ]]; then echo "没有找到已分配的端口。"; return 0; fi

    red "以下是可删除的端口(黄色代表占用该端口,不可删除!)："
    while read -r port typ desc; do
        [[ $port =~ ^[0-9]+$ ]] || continue
        if port_in_use "$port"; then yellow "$port $typ $desc【已被占用】"
        else green "$port $typ $desc【未被占用】"; fi
    done <<< "$list"

    while true; do
        ask choice "请输入要删除的端口号（直接按Enter删除一个未占用的端口）: "
        if [[ -z $choice ]]; then
            while read -r port typ desc; do
                [[ $port =~ ^[0-9]+$ ]] || continue
                if ! port_in_use "$port"; then choice=$port; break; fi
            done <<< "$list"
            if [[ -z $choice ]]; then red "没有可删除的未占用端口。"; return 1; fi
            green "自动选择删除端口: $choice"
        fi

        typ=$(awk -v p="$choice" '$1 == p {print $2}' <<< "$list")
        if [[ -z $typ ]]; then
            red "输入的端口号无效或不在可删除的列表中，请重新输入。"
            continue
        fi
        if port_in_use "$choice"; then
            yellow "端口 $choice 被占用，无法删除。"
            return 1
        fi
        devil port del "$typ" "$choice" >/dev/null 2>&1
        if devil port list 2>/dev/null | awk -v p="$choice" '$1 == p {f=1} END {exit !f}'; then
            red "删除端口失败: $choice"
            return 1
        fi
        red "已成功删除端口: $choice"
        return 0
    done
}

# alloc_port 描述 协议(tcp|udp) 结果变量名
alloc_port() {
    local name=$1 proto=$2 var=$3 key="$2|$1" cur ans
    load_ports
    cur=${PORT_MAP[$key]:-}

    if [[ -n $cur ]]; then
        green "当前已存在 $name 的端口"
        yellow "已分配的 $name $proto 端口为 : $cur"
        ask ans "是否重新分配 $name 端口($cur)？[y/n Enter默认: n]: " n
        if [[ $ans =~ ^[Yy]$ ]]; then
            devil port del "$proto" "$cur" >/dev/null 2>&1
            load_ports
            if [[ -n ${PORT_MAP[$key]:-} ]]; then
                red "删除 $name 端口失败: $cur"
            else
                yellow "已成功删除 $name 端口: $cur"
                cur=""
            fi
        fi
    fi

    if [[ -z $cur ]]; then
        if (( $(count_ports) >= 3 )); then
            delete_unused_port || return 1
        fi
        red "正在检测面板开放的端口，并重新分配....."
        devil port add "$proto" random "$name" >/dev/null 2>&1
        load_ports
        cur=${PORT_MAP[$key]:-}
        if [[ -z $cur ]]; then
            red "端口分配失败：$name ($proto)，请到面板检查端口配额。"
            return 1
        fi
        green "自动分配 ${name} 端口为: ${cur}"
    fi

    printf -v "$var" '%s' "$cur"
    green "你的 $name $proto 端口为: $cur"
    sleep 1
}

# ------------------------------------------------------------------------------
# 下载
# ------------------------------------------------------------------------------
# download_file URL 目标路径
download_file() {
    local url=$1 dest=$2 key tmp size sum exp
    key=${url##*/}
    tmp="$dest.part"
    if ! curl -fL -sS --retry 3 --connect-timeout 15 -o "$tmp" "$url"; then
        rm -f "$tmp"
        red "下载失败，请检查网络连接: $url"
        return 1
    fi
    size=$(stat -f%z "$tmp" 2>/dev/null || echo 0)
    if (( size < 100000 )); then
        rm -f "$tmp"
        red "下载的文件异常（体积过小: ${size} 字节）: $url"
        return 1
    fi
    sum=$(sha256 -q "$tmp" 2>/dev/null)
    exp=${EXPECTED_SHA256[$key]:-}
    if [[ -n $exp && $sum != "$exp" ]]; then
        rm -f "$tmp"
        red "sha256 校验失败: $key"
        return 1
    fi
    [[ -z $exp ]] && yellow "$key sha256: $sum（未设置校验值，已跳过校验）"
    mv "$tmp" "$dest"
    chmod +x "$dest"
}

download_singbox() {
    local arch web_url bot_url pair name url
    arch=$(uname -m)
    case $arch in
        arm|arm64|aarch64) web_url="$GH_BASE/arm64-sb";    bot_url="$GH_BASE/arm64-bot13" ;;
        amd64|x86_64|x86)  web_url="$GH_BASE/amd64-web";   bot_url="$GH_BASE/amd64-bot" ;;
        *) red "Unsupported architecture: $arch"; return 1 ;;
    esac

    green "正在下载所需配置文件，请稍后......"
    echo
    sleep 1
    for pair in "web|$web_url" "bot|$bot_url"; do
        name=${pair%%|*}; url=${pair#*|}
        if [[ -e $WORKDIR/$name ]]; then
            yellow "所需配置文件已存在，无需下载！"
            chmod +x "$WORKDIR/$name"
        else
            download_file "$url" "$WORKDIR/$name" || return 1
            yellow "下载成功，配置文件已保存"
        fi
    done
}

# ------------------------------------------------------------------------------
# Argo 隧道
# ------------------------------------------------------------------------------
argo_configure() {
    local choice credentials_file tid=""
    if [[ $INSTALL_VMESS != true ]]; then
        green "没有选择 vmess 协议，暂停使用 Argo 固定隧道"
        return 0
    fi

    while true; do
        ask choice "Y 固定Argo隧道 或者 N 使用临时隧道【y/n】(ENTER默认y): " y
        case $choice in
            [Yy]) green "开启固定隧道功能，请稍后..."; sleep 2; break ;;
            [Nn])
                green "将使用临时隧道..."
                red "注意: 临时隧道不稳定, 可能会出现不通，建议固定隧道！"
                sleep 2
                ARGO_DOMAIN=""; ARGO_AUTH=""
                rm -f "$ARGO_CONF"
                return 0 ;;
            *) red "无效的选择，请输入 y 或 n 或直接按Enter键" ;;
        esac
    done

    yellow "请访问以下网站生成 Argo 固定隧道所需的Json配置信息。"
    echo
    red "      https://fscarmen.cloudflare.now.cc/ "
    echo

    local new_domain new_auth
    while true; do
        ask new_domain "请输入 Argo 固定隧道域名${ARGO_DOMAIN:+ [回车沿用: $ARGO_DOMAIN]}: " "$ARGO_DOMAIN"
        if [[ $new_domain =~ ^[A-Za-z0-9.-]+$ ]]; then break; fi
        red "Argo 固定隧道域名为空或格式不正确，请重新输入。"
    done
    ARGO_DOMAIN=$new_domain
    green "你的 Argo 固定隧道域名为: $ARGO_DOMAIN"

    while true; do
        ask new_auth "请输入 Argo 固定隧道密钥（Json 或 Token）${ARGO_AUTH:+ [回车沿用已保存的密钥]}: " "$ARGO_AUTH"
        if [[ $new_auth =~ ^[A-Za-z0-9=_+/-]{120,250}$ || $new_auth == *TunnelSecret* ]]; then break; fi
        red "密钥为空或格式不正确（应为 Token 或包含 TunnelSecret 的 Json），请重新输入。"
    done
    ARGO_AUTH=$new_auth

    if [[ $ARGO_AUTH == *TunnelSecret* ]]; then
        if ! ( umask 077; printf '%s' "$ARGO_AUTH" > "$WORKDIR/tunnel.json" ); then
            red "生成 tunnel.json 文件失败，请检查权限和路径"
            return 1
        fi
        credentials_file="$WORKDIR/tunnel.json"
        tid=$(_json_get "$ARGO_AUTH" TunnelID)
    else
        credentials_file="/dev/null"
        yellow "注意：使用 token，需要在 Cloudflare 后台设置隧道端口(${vmess_port})和面板开放的 TCP 端口一致"
    fi

    cat > "$WORKDIR/tunnel.yml" <<EOF
tunnel: $tid
credentials-file: $credentials_file
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$vmess_port
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
    if [[ $? -ne 0 ]]; then
        red "生成 tunnel.yml 文件失败，请检查权限和路径"
        return 1
    fi
    save_argo_conf
}

build_bot_args() {
    local vp=${1:-8080}
    if [[ $ARGO_AUTH =~ ^[A-Za-z0-9=_+/-]{120,250}$ ]]; then
        BOT_ARGS=(tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token "$ARGO_AUTH")
    elif [[ $ARGO_AUTH == *TunnelSecret* ]]; then
        BOT_ARGS=(tunnel --edge-ip-version auto --config "$WORKDIR/tunnel.yml" run)
    else
        BOT_ARGS=(tunnel --edge-ip-version auto --no-autoupdate --protocol http2
                  --logfile "$WORKDIR/boot.log" --loglevel info --url "http://localhost:$vp")
    fi
}

start_bot() {
    local vp
    if [[ ! -e $WORKDIR/bot ]]; then
        green "没有找到 bot 文件，无法启动 bot 进程。"
        return 1
    fi
    chmod +x "$WORKDIR/bot"
    stop_proc bot >/dev/null
    vp=${vmess_port:-$(config_vmess_port)}
    build_bot_args "${vp:-8080}"
    [[ -z $ARGO_AUTH ]] && rm -f "$WORKDIR/boot.log"
    nohup "$WORKDIR/bot" "${BOT_ARGS[@]}" >/dev/null 2>&1 </dev/null &
    sleep 2
    if proc_running bot; then
        green "BOT进程启动成功, 并正在运行！"
    else
        red "bot进程启动失败，请检查配置或日志以获取更多信息。"
        return 1
    fi
}

get_argodomain() {
    local i d
    if [[ -n $ARGO_AUTH ]]; then echo "$ARGO_DOMAIN"; return; fi
    for ((i = 0; i < 20; i++)); do
        d=$(grep -oE 'https://[[:alnum:].-]+\.trycloudflare\.com' "$WORKDIR/boot.log" 2>/dev/null |
            tail -n 1 | sed 's#https://##')
        if [[ -n $d ]]; then echo "$d"; return; fi
        sleep 1
    done
}

# ------------------------------------------------------------------------------
# 服务启停
# ------------------------------------------------------------------------------
start_service() {
    if [[ -f $base_dir/.enabled_flag ]]; then
        printf '%s=== Enabled 已为你自动已开启===  注意：第一次开启Enabled后，请重启服务器后生效，切记！！！%s\n' "$C_G" "$C_0"
        return
    fi
    if devil binexec on >/dev/null 2>&1; then
        printf '%s=== Enabled 已为你自动已开启===  注意：第一次开启Enabled后，请重启服务器后生效，切记！！！%s\n' "$C_G" "$C_0"
        touch "$base_dir/.enabled_flag"
    else
        red "Enabled未开启，请尝试手动开启."
    fi
}

start_npm() {
    local tls=()
    [[ -e $WORKDIR/npm ]] || return 0
    if [[ -n $NEZHA_SERVER && -n $NEZHA_PORT && -n $NEZHA_KEY ]]; then
        case " 443 8443 2096 2087 2083 2053 " in *" $NEZHA_PORT "*) tls=(--tls) ;; esac
        stop_proc npm >/dev/null
        TMPDIR=$WORKDIR nohup "$WORKDIR/npm" -s "${NEZHA_SERVER}:${NEZHA_PORT}" -p "${NEZHA_KEY}" "${tls[@]}" \
            >/dev/null 2>&1 </dev/null &
        sleep 2
        proc_running npm && green "npm is running" || red "npm is not running"
    else
        purple "NEZHA variable is empty, skipping running"
    fi
}

start_web_proc() {
    local out
    if [[ ! -e $WORKDIR/web ]]; then
        red "web可执行文件未找到，请检查路径是否正确。"
        return 1
    fi
    chmod +x "$WORKDIR/web"
    stop_proc web >/dev/null
    if ! out=$("$WORKDIR/web" check -c "$WORKDIR/config.json" 2>&1); then
        red "配置文件检查失败："
        echo "$out"
        return 1
    fi
    nohup "$WORKDIR/web" run -c "$WORKDIR/config.json" >"$WORKDIR/web.log" 2>&1 </dev/null &
    sleep 2
    if proc_running web; then
        green "WEB进程启动成功,并正在运行！"
    else
        red "web进程启动失败，请重试。最近日志："
        tail -n 10 "$WORKDIR/web.log" 2>/dev/null
        return 1
    fi
}

run_sb() {
    start_npm
    start_web_proc || return 1
    if [[ $ARGO_CONFIGURED == true ]]; then start_bot; fi
    return 0
}

vmess_link() {   # 名称 地址 端口 host tls sni
    local json
    json=$(printf '{ "v": "2", "ps": "%s", "add": "%s", "port": "%s", "id": "%s", "aid": "0", "scy": "none", "net": "ws", "type": "none", "host": "%s", "path": "/vmess?ed=2048", "tls": "%s", "sni": "%s", "alpn": "", "fp": ""}' \
        "$1" "$2" "$3" "$UUID" "$4" "$5" "$6")
    printf 'vmess://%s' "$(printf '%s' "$json" | b64)"
}

# 菜单 6：启动服务
start_web() {
    local argodomain node_name="${USERNAME}-${SUBDOMAIN}"
    red "正在启动sing-box服务,请稍后......"
    sleep 1
    start_web_proc

    if [[ -n $ARGO_AUTH ]] || config_has_vmess; then
        if start_bot; then
            if [[ -n $ARGO_AUTH ]]; then
                green "=== Argo固定隧道功能已开启 ==="
            elif config_has_vmess; then
                green "===Argo临时隧道功能已开启==="
                yellow "正在等待临时隧道域名..."
                argodomain=$(get_argodomain)
                if [[ -n $argodomain ]]; then
                    echo
                    red "以下为新vmess开启隧道功能链接，替换www.visa.com.tw为自己的优选ip可获得极致体验"
                    printf '%s%s%s\n\n' "$C_Y" \
                        "$(vmess_link "$node_name" "$CFIP" "$CFPORT" "$argodomain" tls "$argodomain")" "$C_0"
                else
                    red "未能获取临时隧道域名，请稍后查看 $WORKDIR/boot.log"
                fi
            fi
        fi
    else
        red "===Argo隧道未开启==="
    fi
}

# 菜单 7：停止所有服务
stop_web() {
    local item label
    yellow "正在清理 web 和 bot 进程，请稍后......"
    sleep 1
    for item in "web|WEB" "bot|BOT" "npm|NPM" "socks5|SOCKS5"; do
        label=${item#*|}
        if stop_proc "${item%%|*}"; then
            red "已成功停止 $label 进程!"
        else
            red "未找到$label进程，可能已经停止了!"
        fi
    done
    sleep 1
}

# ------------------------------------------------------------------------------
# 配置生成
# ------------------------------------------------------------------------------
_cfg_emit() { printf '%s' "$_CFG_SEP" >> "$_CFG_FILE"; cat >> "$_CFG_FILE"; _CFG_SEP=$',\n'; }

generate_config() {
    local out private_key="" cert="$WORKDIR/cert.pem" key="$WORKDIR/private.key"
    REALITY_PUB=""

    if [[ -z "${vless_port}${vmess_port}${hy2_port}${tuic_port}" ]]; then
        red "Error: No port number provided. Configuration file will not be generated."
        return 1
    fi

    if [[ $INSTALL_VLESS == true ]]; then
        out=$("$WORKDIR/web" generate reality-keypair 2>&1)
        private_key=$(awk '/PrivateKey:/ {print $2}' <<< "$out")
        REALITY_PUB=$(awk '/PublicKey:/ {print $2}' <<< "$out")
        if [[ -z $private_key || -z $REALITY_PUB ]]; then
            red "生成 Reality 密钥失败: $out"
            return 1
        fi
    fi

    if [[ $INSTALL_HYSTERIA2 == true || $INSTALL_TUIC == true ]]; then
        if ! { openssl ecparam -genkey -name prime256v1 -out "$key" 2>/dev/null &&
               openssl req -new -x509 -days 3650 -key "$key" -out "$cert" -subj "/CN=$(hostname)" 2>/dev/null; }; then
            red "生成 TLS 证书失败"
            return 1
        fi
        chmod 600 "$key"
    fi

    _CFG_FILE="$WORKDIR/config.template.json"
    _CFG_SEP=""
    cat > "$_CFG_FILE" <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "output": "$WORKDIR/sb.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "cloudflare",
        "address": "https://1.1.1.1/dns-query",
        "strategy": "prefer_ipv4",
        "detour": "direct"
      },
      {
        "tag": "google",
        "address": "tls://8.8.8.8",
        "strategy": "prefer_ipv4",
        "detour": "direct"
      }
    ],
    "final": "cloudflare",
    "strategy": "prefer_ipv4",
    "disable_cache": false,
    "disable_expire": false
  },
  "inbounds": [
EOF

    if [[ $INSTALL_VLESS == true ]]; then
        _cfg_emit <<EOF
    {
      "tag": "vless-reality-version",
      "type": "vless",
      "listen": "::",
      "listen_port": $vless_port,
      "users": [
        {
          "uuid": "$UUID",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.ups.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.ups.com",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": [""]
        }
      }
    }
EOF
    fi

    if [[ $INSTALL_VMESS == true ]]; then
        _cfg_emit <<EOF
    {
      "tag": "vmess-ws-in",
      "type": "vmess",
      "listen": "::",
      "listen_port": $vmess_port,
      "users": [
        {
          "uuid": "$UUID"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess",
        "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    }
EOF
    fi

    if [[ $INSTALL_HYSTERIA2 == true ]]; then
        _cfg_emit <<EOF
    {
      "tag": "hysteria-in",
      "type": "hysteria2",
      "listen": "__IP_ADDRESS__",
      "listen_port": $hy2_port,
      "users": [
        {
          "password": "$UUID"
        }
      ],
      "masquerade": "https://bing.com",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "$cert",
        "key_path": "$key"
      }
    }
EOF
    fi

    if [[ $INSTALL_TUIC == true ]]; then
        _cfg_emit <<EOF
    {
      "tag": "tuic-in",
      "type": "tuic",
      "listen": "__IP_ADDRESS__",
      "listen_port": $tuic_port,
      "users": [
        {
          "uuid": "$UUID",
          "password": "$TUIC_PASS"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "$cert",
        "key_path": "$key"
      }
    }
EOF
    fi

    cat >> "$_CFG_FILE" <<EOF

  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "direct",
      "tag": "direct-ipv4-prefer-out",
      "domain_strategy": "prefer_ipv4"
    },
    {
      "type": "direct",
      "tag": "direct-ipv4-only-out",
      "domain_strategy": "ipv4_only"
    },
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "engage.cloudflareclient.com",
      "server_port": 2408,
      "local_address": [
        "$WG_ADDR_V4",
        "$WG_ADDR_V6"
      ],
      "private_key": "$WG_PRIVATE_KEY",
      "peer_public_key": "$WG_PEER_PUBLIC_KEY",
      "mtu": 1420,
      "reserved": [$WG_RESERVED]
    },
    {
      "type": "direct",
      "tag": "wireguard-ipv4-prefer-out",
      "detour": "wireguard-out",
      "domain_strategy": "prefer_ipv4"
    },
    {
      "type": "direct",
      "tag": "wireguard-ipv4-only-out",
      "detour": "wireguard-out",
      "domain_strategy": "ipv4_only"
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "geosite-netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
        "update_interval": "1d"
      }
    ],
    "rules": [
      {
        "rule_set": [
          "geosite-netflix"
        ],
        "outbound": "wireguard-ipv4-only-out"
      },
      {
        "domain": [
          "api.statsig.com",
          "browser-intake-datadoghq.com",
          "cdn.openai.com",
          "chat.openai.com",
          "auth.openai.com",
          "chat.openai.com.cdn.cloudflare.net",
          "ios.chat.openai.com",
          "o33249.ingest.sentry.io",
          "openai-api.arkoselabs.com",
          "openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net",
          "openaicomproductionae4b.blob.core.windows.net",
          "production-openaicom-storage.azureedge.net",
          "static.cloudflareinsights.com"
        ],
        "domain_suffix": [
          ".algolia.net",
          ".auth0.com",
          ".chatgpt.com",
          ".challenges.cloudflare.com",
          ".client-api.arkoselabs.com",
          ".events.statsigapi.net",
          ".featuregates.org",
          ".identrust.com",
          ".intercom.io",
          ".intercomcdn.com",
          ".launchdarkly.com",
          ".oaistatic.com",
          ".oaiusercontent.com",
          ".observeit.net",
          ".openai.com",
          ".openaiapi-site.azureedge.net",
          ".openaicom.imgix.net",
          ".segment.io",
          ".sentry.io",
          ".stripe.com"
        ],
        "domain_keyword": [
          "openaicom-api"
        ],
        "outbound": "wireguard-ipv4-prefer-out"
      }
    ],
    "final": "direct"
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "$WORKDIR/cache.db",
      "cache_id": "mycacheid",
      "store_fakeip": true
    }
  }
}
EOF

    [[ -f $WORKDIR/config.json ]] && cp "$WORKDIR/config.json" "$WORKDIR/config.json.bak"
    sed "s/__IP_ADDRESS__/${FINAL_IP}/g" "$_CFG_FILE" > "$WORKDIR/config.json"
    chmod 600 "$WORKDIR/config.json" "$_CFG_FILE"
    printf '%s\n' "$FINAL_IP" > "$base_dir/current_active_ip.txt"
    green "配置文件模板和初始配置文件已生成。"
    green "当前活动IP ${FINAL_IP} 已被记录。"
}

# 生成节点链接：list.txt 里只写纯文本，不带颜色码
get_links() {
    local argodomain="" node_name="${USERNAME}-${SUBDOMAIN}"

    if [[ $ARGO_CONFIGURED == true ]]; then
        yellow "正在获取隧道域名..."
        argodomain=$(get_argodomain)
        printf '%sArgoDomain:%s%s%s\n\n' "$C_G" "$C_P" "$argodomain" "$C_0"
    fi
    sleep 1

    if [[ $ARGO_CONFIGURED == true && -n $ARGO_AUTH ]]; then
        green "=== Argo固定隧道功能已开启 ==="
    elif [[ $ARGO_CONFIGURED == true && -n $argodomain ]]; then
        green "===Argo临时隧道功能已开启==="
    else
        red "===Argo隧道功能未开启==="
    fi

    [[ $FQDN == *.serv00.com ]] && green "当前服务器的地址是：$FQDN"
    echo
    red "注意：v2ray或其他软件的跳过证书验证需设置为true, 否则hy2或tuic节点可能不通"
    echo

    {
        if [[ $INSTALL_VLESS == true ]]; then
            echo "以下为vless客户端通用链接"
            echo
            echo "vless://$UUID@$FINAL_IP:$vless_port/?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.ups.com&fp=chrome&pbk=$REALITY_PUB&type=tcp&headerType=none#$node_name"
            echo
        fi
        if [[ $INSTALL_VMESS == true ]]; then
            echo "以下为vmess客户端通用链接"
            echo
            vmess_link "$node_name" "$FINAL_IP" "$vmess_port" "" "" ""; echo
            echo
            if [[ $ARGO_CONFIGURED == true && -n $argodomain ]]; then
                echo "以下为vmess开启隧道功能链接，替换$CFIP为自己的优选ip可获得极致体验"
                echo
                vmess_link "$node_name" "$CFIP" "$CFPORT" "$argodomain" tls "$argodomain"; echo
                echo
            fi
        fi
        if [[ $INSTALL_HYSTERIA2 == true ]]; then
            echo "以下为HYSTERIA2客户端通用链接"
            echo
            echo "hysteria2://$UUID@$FINAL_IP:$hy2_port/?sni=www.bing.com&alpn=h3&insecure=1#$node_name"
            echo
        fi
        if [[ $INSTALL_TUIC == true ]]; then
            echo "以下为TUIC客户端通用链接"
            echo
            echo "tuic://$UUID:$TUIC_PASS@$FINAL_IP:$tuic_port?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#$node_name"
            echo
        fi
    } > "$WORKDIR/list.txt"
    chmod 600 "$WORKDIR/list.txt"

    printf '%s' "$C_Y"; cat "$WORKDIR/list.txt"; printf '%s' "$C_0"
    green "节点信息已保存"
    green "Running done!"
}

# ------------------------------------------------------------------------------
# 安装 sing-box
# ------------------------------------------------------------------------------
display_options() {
    green "请选择需要安装的服务（请输入对应的序号）："
    yellow "1: vless-reality"
    yellow "2: vmess"
    yellow "3: hysteria2"
    yellow "4: tuic"
    yellow "5: 安装两个协议"
    yellow "6: 安装三个协议"
    yellow "0: 退出安装"
}

# 返回 1 表示用户选择退出
select_protocols() {
    local choices want c list seen
    INSTALL_VLESS=false; INSTALL_VMESS=false; INSTALL_HYSTERIA2=false; INSTALL_TUIC=false
    while true; do
        display_options
        ask choices "请输入你的选择: "
        sleep 1
        if [[ ! $choices =~ ^[0-6]$ ]]; then
            red "输入错误，请输入有效的序号（范围为0-6）!"
            continue
        fi
        if [[ $choices == 0 ]]; then
            red "已退出安装！"
            return 1
        fi

        want=1
        case $choices in
            5) want=2; yellow "请选择要安装的两个协议（请输入对应的序号，用空格分隔）"; ask choices "请输入你的选择: " ;;
            6) want=3; yellow "请选择要安装的三个协议（请输入对应的序号，用空格分隔）"; ask choices "请输入你的选择: " ;;
        esac

        list=(); seen=" "
        for c in $choices; do
            if [[ ! $c =~ ^[1-4]$ ]]; then list=(); break; fi
            [[ $seen == *" $c "* ]] && continue
            seen+="$c "
            list+=("$c")
        done
        if (( ${#list[@]} != want )); then
            red "输入错误，请输入 $want 个不重复的有效序号（范围为1-4）!"
            continue
        fi
        for c in "${list[@]}"; do
            case $c in
                1) INSTALL_VLESS=true ;;
                2) INSTALL_VMESS=true ;;
                3) INSTALL_HYSTERIA2=true ;;
                4) INSTALL_TUIC=true ;;
            esac
        done
        return 0
    done
}

install_singbox() {
    local choice argo_choice
    printf '%s本脚本可以选择性安装四种协议 %s(vless-reality||vmess||hysteria2||tuic)%s\n' "$C_Y" "$C_P" "$C_0"
    printf '%s注意：脚本全自动化交互安装,无需登陆面板 %s<<端口会根据用户选择的协议来进行自动分配>>%s\n' "$C_Y" "$C_P" "$C_0"
    start_service

    while true; do
        ask choice "确定继续安装吗?<ENTER默认安装>【y/n】: " y
        if [[ $choice =~ ^[Yy]$ ]]; then break
        elif [[ $choice =~ ^[Nn]$ ]]; then red "安装已取消"; return 0
        else red "无效输入，请重新输入！！！"; fi
    done

    mkdir -p "$WORKDIR"
    cd "$WORKDIR" || { red "无法进入 $WORKDIR"; return 1; }

    select_protocols || return 0

    vless_port=""; vmess_port=""; hy2_port=""; tuic_port=""
    ARGO_CONFIGURED=false

    if [[ $INSTALL_VLESS == true ]]; then
        alloc_port "vless-reality" tcp vless_port || return 1
    fi
    if [[ $INSTALL_VMESS == true ]]; then
        alloc_port "vmess" tcp vmess_port || return 1
        ask argo_choice "是否使用Argo功能?<ENTER默认开启>【y/n】: " y
        if [[ $argo_choice =~ ^[Yy]$ ]]; then
            argo_configure || return 1
            ARGO_CONFIGURED=true
        else
            ARGO_DOMAIN=""; ARGO_AUTH=""
            rm -f "$ARGO_CONF"
            green "跳过Argo功能配置..."
        fi
    fi
    if [[ $INSTALL_HYSTERIA2 == true ]]; then
        alloc_port "hysteria2" udp hy2_port || return 1
    fi
    if [[ $INSTALL_TUIC == true ]]; then
        alloc_port "Tuic" udp tuic_port || return 1
    fi

    echo
    download_singbox || return 1
    echo
    get_ip || return 1
    generate_config || return 1

    [[ $INSTALL_VLESS == true ]]     && green "正在配置 VLESS，请稍后..."
    [[ $INSTALL_VMESS == true ]]     && green "正在配置 VMESS，请稍后..."
    [[ $INSTALL_HYSTERIA2 == true ]] && green "正在配置 Hysteria2，请稍后..."
    [[ $INSTALL_TUIC == true ]]      && green "正在配置 TUIC，请稍后..."

    run_sb || { red "服务启动失败，安装中止。"; return 1; }
    sleep 2
    get_links

    [[ -n $ARGO_DOMAIN ]] && printf '%s隧道域名: %s%s\n' "$C_Y" "$ARGO_DOMAIN" "$C_0"
    purple "安装已完成！"
}

# ------------------------------------------------------------------------------
# Socks5
# ------------------------------------------------------------------------------
setup_socks5() {
    local ans user_port s5_user s5_pass again IP socks_bin="$WORKDIR/socks5"
    local socks_url="$GH_BASE/socks5"

    ask ans "是否安装 Socks5 代理？(Y/N 回车N) " n
    if [[ ! $ans =~ ^[Yy]$ ]]; then
        yellow "已取消安装 Socks5 代理。"
        return 0
    fi
    mkdir -p "$WORKDIR"

    get_ip || return 1
    IP=$FINAL_IP
    yellow "设备的IP地址是: ${IP}"
    yellow "本机域名是: ${SERV_DOMAIN}"

    ask user_port "请输入 socks5 端口,按下ENTER自动检测 (面板开放的TCP端口): "
    if [[ $user_port =~ ^[0-9]+$ ]] && (( user_port >= 1 && user_port <= 65535 )); then
        socks5_port=$user_port
        yellow "使用手动指定的端口: $socks5_port（请确认该端口已在面板开放）"
    else
        [[ -n $user_port ]] && red "端口输入无效，改为自动检测。"
        alloc_port "socks5" tcp socks5_port || return 1
    fi

    ask s5_user "请输入 socks5 用户名（按回车生成随机用户名）: "
    if [[ -z $s5_user ]]; then
        s5_user=$(rand_str 6)
        yellow "随机生成的 socks5 用户名是: ${s5_user}"
    fi

    while true; do
        ask s5_pass "请输入 socks5 密码（按回车生成随机密码，不能包含@和:）: "
        if [[ -z $s5_pass ]]; then
            s5_pass=$(rand_str 10)
            yellow "随机生成的 socks5 密码是: ${s5_pass}"
            break
        elif [[ $s5_pass == *@* || $s5_pass == *:* ]]; then
            red "密码不能包含 @ 和 :，请重新输入。"
        else
            break
        fi
    done

    yellow "创建配置文件: ${WORKDIR}/socks.json"
    ( umask 077; cat > "$WORKDIR/socks.json" <<EOF
{
  "log": {
    "access": "/dev/null",
    "error": "/dev/null",
    "loglevel": "none"
  },
  "inbounds": [
    {
      "port": "$socks5_port",
      "protocol": "socks",
      "tag": "socks",
      "settings": {
        "auth": "password",
        "udp": false,
        "ip": "0.0.0.0",
        "userLevel": 0,
        "accounts": [
          {
            "user": "$s5_user",
            "pass": "$s5_pass"
          }
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
EOF
    )

    if [[ ! -e $socks_bin ]]; then
        yellow "下载 socks5 程序..."
        download_file "$socks_url" "$socks_bin" || return 1
    else
        ask again "socks5 程序已存在，是否重新下载？(Y/N 回车N): " n
        if [[ $again =~ ^[Yy]$ ]]; then
            yellow "重新下载 socks5 程序..."
            stop_proc socks5 >/dev/null
            rm -f "$socks_bin"
            download_file "$socks_url" "$socks_bin" || return 1
        fi
    fi

    chmod +x "$socks_bin"
    stop_proc socks5 >/dev/null
    nohup "$socks_bin" -c "$WORKDIR/socks.json" >/dev/null 2>&1 </dev/null &
    sleep 1

    if proc_running socks5; then
        green "Socks5 代理程序启动成功"
        yellow "Socks5 代理地址： $IP:$socks5_port 用户名：$s5_user 密码：$s5_pass"
        echo
        yellow "socks://${s5_user}:${s5_pass}@${SERV_DOMAIN}:${socks5_port}"
        {
            echo "Socks5 代理地址： $IP:$socks5_port 用户名：$s5_user 密码：$s5_pass"
            echo
            echo "socks://${s5_user}:${s5_pass}@${SERV_DOMAIN}:${socks5_port}"
            echo
        } > "$WORKDIR/socks5.txt"
        chmod 600 "$WORKDIR/socks5.txt"
        echo
    else
        red "Socks5 代理程序启动失败"
    fi
}

# ------------------------------------------------------------------------------
# 更换 IP
# ------------------------------------------------------------------------------
change_ip() {
    local old_ip new_ip="" ips=() ip i choice old_re
    if [[ ! -f $WORKDIR/config.template.json || ! -f $base_dir/current_active_ip.txt ]]; then
        red "错误：sing-box未安装或配置文件不完整，无法更换IP。"
        red "请先执行安装流程。"
        return 1
    fi

    old_ip=$(<"$base_dir/current_active_ip.txt")
    yellow "当前正在使用的IP是: ${old_ip}"
    yellow "正在自动检测所有可用的IP地址..."
    mapfile -t ips < <(fetch_unblock_ips)

    if (( ${#ips[@]} == 0 )); then
        red "未能检测到任何可用的IP地址，无法更换。请稍后重试。"
        return 1
    fi

    green "检测到以下可用IP地址："
    i=1
    for ip in "${ips[@]}"; do green "  [$i] $ip"; i=$((i + 1)); done
    echo
    ask choice "请选择一个新IP (输入编号, 或直接按Enter随机选择): "
    if [[ -z $choice ]]; then
        new_ip=${ips[RANDOM % ${#ips[@]}]}
        green "已为您随机选择新IP: $new_ip"
    elif [[ $choice =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#ips[@]} )); then
        new_ip=${ips[choice-1]}
        green "您已选择新IP: $new_ip"
    else
        red "无效输入，操作已取消。"
        return 1
    fi

    if [[ $new_ip == "$old_ip" ]]; then
        green "您选择的IP与当前IP相同，无需更改。"
        return 0
    fi

    purple "--> 正在更新核心配置文件..."
    [[ -f $WORKDIR/config.json ]] && cp "$WORKDIR/config.json" "$WORKDIR/config.json.bak"
    sed "s/__IP_ADDRESS__/${new_ip}/g" "$WORKDIR/config.template.json" > "$WORKDIR/config.json"
    chmod 600 "$WORKDIR/config.json"

    purple "--> 正在更新节点链接..."
    if [[ -f $WORKDIR/list.txt ]]; then
        old_re=${old_ip//./\\.}
        sed "s#${old_re}#${new_ip}#g" "$WORKDIR/list.txt" > "$WORKDIR/list.txt.new" &&
            mv "$WORKDIR/list.txt.new" "$WORKDIR/list.txt"
    fi

    purple "--> 正在更新当前IP状态记录..."
    printf '%s\n' "$new_ip" > "$base_dir/current_active_ip.txt"
    SERVER_INFO_CACHE=""

    purple "--> 正在重启sing-box服务以应用新IP..."
    if start_web_proc; then
        green "服务重启成功！IP已成功更换为: ${new_ip}"
        echo
        purple "以下是更新后的节点信息："
        if [[ -f $WORKDIR/list.txt ]]; then
            printf '%s' "$C_Y"; cat "$WORKDIR/list.txt"; printf '%s' "$C_0"
        else
            red "错误：找不到节点信息文件 list.txt"
        fi
    else
        red "错误：服务重启失败！请检查问题，或尝试手动重启。"
    fi
}

# ------------------------------------------------------------------------------
# 卸载 / 清理 / 初始化
# ------------------------------------------------------------------------------
uninstall_singbox() {
    local choice item
    purple "正在卸载 sing-box，请稍后..."
    ask choice "确定要卸载吗? (ENTER默认:y)【y/n】: " y
    case $choice in
        [Yy])
            for item in web bot npm socks5; do
                if stop_proc "$item"; then purple "已终止 $item 进程。"; fi
            done
            cd "$HOME" || true
            if [[ -n $WORKDIR && $WORKDIR != "$HOME" && $WORKDIR != / && -d $WORKDIR ]]; then
                rm -rf "$WORKDIR"
                purple "已删除程序配置文件"
            fi
            rm -f "$ARGO_CONF" "$base_dir/current_active_ip.txt" "$ip_file_cache"
            ARGO_DOMAIN=""; ARGO_AUTH=""
            purple "卸载完成！（UUID 等少量记录保留在 $base_dir）"
            ;;
        [Nn]) purple "已取消卸载。" ;;
        *)    red "无效的选择，请输入 y 或 n" ;;
    esac
}

# 菜单 5
manage_processes() {
    local choice
    red "请选择要执行的操作:"
    red "1. 清理所有进程,可能会断开ssh连接"
    red "2. 只清理当前用户的进程(保留当前终端会话)"
    echo
    ask choice "输入选择 (1 或 2): "
    echo
    case $choice in
        1)
            red "正在清理系统所有进程,请稍后......"
            sleep 2
            pkill -KILL -u "$USERNAME" ;;
        2)
            red "正在清理当前用户进程,请稍后......"
            kill_user_procs_except_self TERM
            sleep 2
            kill_user_procs_except_self KILL
            echo ;;
        *) red "无效的选择。" ;;
    esac
    sleep 1
}

# 菜单 8
cleanup_and_delete() {
    local ans item
    yellow "准备初始化系统，请稍后..."
    sleep 1
    red "警告: 此操作将会删除 $HOME 下除 backups 以外的所有文件，并终止所有进程!"
    red "      网站目录(domains)、数据库配置文件等都会丢失，且无法恢复。"
    ask ans "确认请输入大写 YES，其他任意输入取消: "
    if [[ $ans != YES ]]; then
        green "操作已取消。"
        return 0
    fi
    if [[ -z $HOME || $HOME == / || ! -d $HOME ]]; then
        red "HOME 目录异常，已中止。"
        return 1
    fi

    red "--> 正在终止所有用户进程..."
    for item in web bot npm socks5; do stop_proc "$item" >/dev/null; done
    kill_user_procs_except_self KILL
    sleep 2
    yellow "--> 重要提示: 所有用户进程已终止。"

    red "--> 正在删除用户主目录下的所有文件..."
    cd "$HOME" || true
    find "$HOME" -mindepth 1 -maxdepth 1 ! -name backups -exec rm -rf {} + 2>/dev/null

    if [[ -z $(find "$HOME" -mindepth 1 -maxdepth 1 ! -name backups 2>/dev/null) ]]; then
        green "已成功初始化系统! "
        exit 0
    else
        red "删除操作出现问题，请检查是否有权限问题或其他错误。"
    fi
}

show_nodes() {
    if [[ -f $WORKDIR/list.txt || -f $WORKDIR/socks5.txt ]]; then
        printf '%s' "$C_Y"
        [[ -f $WORKDIR/list.txt ]] && cat "$WORKDIR/list.txt"
        [[ -f $WORKDIR/socks5.txt ]] && cat "$WORKDIR/socks5.txt"
        printf '%s' "$C_0"
    else
        red "节点信息文件不存在，请先安装服务。"
    fi
}

# ------------------------------------------------------------------------------
# 主菜单
# ------------------------------------------------------------------------------
status_installed() {
    if [[ -e $WORKDIR/web ]]; then green "欢迎使用SINGBOX服务"; else red "sing-box当前未安装!"; fi
}
status_running() {
    if proc_running web; then green "sing-box Running！"; else red "sing-box Not Running"; fi
}
box_line() { printf '%s||%s   %s\n' "$C_Y" "$C_0" "$1"; }

menu() {
    local choice
    while true; do
        clear
        echo
        yellow "=== 欢迎使用SERV00|SING-BOX一键安装脚本 ==="
        echo
        orange "=== 脚本支持:VLESS VMESS HY2 TUIC socks5 协议，UUID 自动生成 ==="
        yellow "=== 支持安装：单，双，三个协议(面板最多只能开放3个端口)，自由选择 ==="
        cyan   "=== 固定argo隧道 可以优选ip或优选域名！  ==="
        cyan   "=== argo隧道配置文件生成网址  https://fscarmen.cloudflare.now.cc/ ==="
        yellow "脚本地址：https://github.com/yyf-lbl/singbox-2"
        purple "*****转载请著名出处，请勿滥用*****"
        echo
        get_server_info
        echo

        printf '%s=============================%s\n' "$C_Y" "$C_0"
        box_line ""
        box_line ""
        box_line "$(status_installed)"
        box_line ""
        box_line "$(status_running)"
        box_line ""
        printf '%s=============================%s\n' "$C_Y" "$C_0"
        echo

        green  "1. 安装sing-box";                                     echo "==============="
        printf '%s2. 安装Socks5%s%s(谨慎安装!)%s\n' "$C_G" "$C_0" "$C_Y" "$C_0"; echo "==============="
        cyan   "3. 查看节点信息";                                     echo "==============="
        red    "4. 卸载所有程序";                                     echo "==============="
        yellow "5. 清理系统进程";                                     echo "==============="
        green  "6. 启动sing-box服务";                                 echo "==============="
        purple "7. 停止所有服务";                                     echo "==============="
        purple "8. 系统初始化";                                       echo "==============="
        orange "9. 更换/更新可用 IP";                                 echo "==============="
        red    "0. 退出脚本";                                         echo "==========="
        ask choice "请输入选择(0-9): "
        echo

        case $choice in
            1) install_singbox;    pause; clear ;;
            2) setup_socks5;       pause; clear ;;
            3) show_nodes;         pause; clear ;;
            4) uninstall_singbox;  pause; clear ;;
            5) manage_processes;   pause; clear ;;
            6) start_web;          pause; clear ;;
            7) stop_web;           pause; clear ;;
            8) cleanup_and_delete; pause; clear ;;
            9) change_ip;          pause; clear ;;
            0) exit 0 ;;
            *) red "无效的选项，请输入 0 到 9"; sleep 2 ;;
        esac
    done
}

menu

