#!/bin/bash

# Linux General System Performance Optimization Script
# Features: Time sync, kernel parameter tuning, network optimization, system limit adjustment
# Support: Ubuntu/Debian/CentOS

set -euo pipefail

# Color Output Function Definitions

# Detect compatible echo command
echo=echo
for cmd in echo /bin/echo; do
    $cmd >/dev/null 2>&1 || continue
    if ! $cmd -e "" | grep -qE '^-e'; then
        echo=$cmd
        break
    fi
done

# Define color codes
CSI=$($echo -e "\033[")
CEND="${CSI}0m"
CDGREEN="${CSI}32m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"
CYELLOW="${CSI}1;33m"
CBLUE="${CSI}1;34m"
CMAGENTA="${CSI}1;35m"
CCYAN="${CSI}1;36m"

# Output functions
OUT_ALERT() {
    echo -e "${CYELLOW}[警告] $1${CEND}"
}

OUT_ERROR() {
    echo -e "${CRED}[错误] $1${CEND}"
}

OUT_INFO() {
    echo -e "${CCYAN}[信息] $1${CEND}"
}

OUT_SUCCESS() {
    echo -e "${CGREEN}[成功] $1${CEND}"
}

# System Detection Function

detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian|raspbian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "raspbian|debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    else
        OUT_ERROR "不支持的操作系统！"
        exit 1
    fi
    OUT_INFO "检测到操作系统: $release"
}

# Time Synchronization Configuration

setup_time_sync() {
    OUT_INFO "配置系统时间同步"
    
    if ! command -v chronyd >/dev/null 2>&1; then
        OUT_INFO "安装 chrony 时间同步服务"
        apt-get install -y chrony
    fi
    
    if ! systemctl is-active --quiet chronyd; then
        systemctl enable --now chronyd
    fi
    
    timedatectl set-timezone Asia/Shanghai 2>/dev/null || true
    OUT_SUCCESS "时间同步配置完成"
}

# Random Number Generator Optimization

optimize_random_generator() {
    OUT_INFO "优化随机数生成器性能"
    
    # Install haveged
    if [[ -z "$(command -v haveged)" ]]; then
        OUT_INFO "安装 haveged 改善随机数生成器性能"
        apt install haveged -y
        systemctl enable haveged
    fi
    
    # Install rng-tools
    if [[ -z "$(command -v rngd)" ]]; then
        OUT_INFO "安装 rng-tools 改善随机数生成器性能"
        apt install rng-tools -y
        # Safely enable rng-tools service (skip if it's a symlink)
        systemctl enable rng-tools 2>/dev/null || OUT_INFO "rng-tools service already configured or is a symlink"
    fi
    
    OUT_SUCCESS "随机数生成器优化完成"
}

# KSM Optimization

optimize_ksm() {
    if [[ ! -z "$(command -v ksmtuned)" ]]; then
        OUT_INFO "禁用 ksmtuned"
        systemctl stop ksmtuned
        systemctl disable --now ksmtuned
        echo 2 > /sys/kernel/mm/ksm/run
        apt autoremove ksmtuned -y || true
        OUT_SUCCESS "KSM 优化完成"
    fi
}

# Disable Transparent Huge Pages

disable_hugepages() {
    OUT_INFO "禁用透明大页 (THP)"
    
    cat > /etc/systemd/system/disable-transparent-huge-pages.service << EOF
[Unit]
Description=Disable Transparent Huge Pages (THP)
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=mongod.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null'
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/defrag > /dev/null'

[Install]
WantedBy=basic.target
EOF

    systemctl daemon-reload
    systemctl start disable-transparent-huge-pages
    systemctl enable disable-transparent-huge-pages
    
    OUT_SUCCESS "透明大页禁用完成"
}

# Kernel Parameter Optimization

optimize_kernel_params() {
    OUT_INFO "优化内核参数"
    
    # Calculate memory-related parameters
    local page=$(getconf PAGESIZE)
    local size=$(($(cat /proc/meminfo | grep MemTotal | awk '{print $2}') * 1024))
    local min=$(printf '%d' $(($size / $page / 4 * 1)))
    local avg=$(printf '%d' $(($size / $page / 4 * 2)))
    local max=$(printf '%d' $(($size / $page / 4 * 3)))

    if [ -f /etc/sysctl.conf ]; then
        chattr -i /etc/sysctl.conf
    fi

    cat > /etc/sysctl.conf << EOF
fs.file-max = 6815744

net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_abort_on_overflow = 1
net.ipv4.tcp_fin_timeout = 30

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_frto = 0
net.ipv4.tcp_mtu_probing = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_timestamps = 1

net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = 152,1052,1053,8443,14999

net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv4.conf.all.route_localnet = 1
EOF

    # Add memory-related parameters (non-Proxmox environment)
    if [[ ! -f /etc/issue ]] || [[ "$(cat /etc/issue | grep 'Welcome to the Proxmox Virtual Environment')" == '' ]]; then
        [[ -f /proc/sys/net/ipv4/tcp_mem ]] && echo "net.ipv4.tcp_mem = ${min} ${avg} ${max}" >> /etc/sysctl.conf
        [[ -f /proc/sys/net/ipv4/udp_mem ]] && echo "net.ipv4.udp_mem = ${min} ${avg} ${max}" >> /etc/sysctl.conf
    fi

    # Apply configuration
    ln -fs /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf
    sort -n /etc/sysctl.conf -o /etc/sysctl.conf
    chattr +i /etc/sysctl.conf 2>/dev/null || true
    sysctl -p && sysctl --system
    
    OUT_SUCCESS "内核参数优化完成"
}

# Kernel Module Configuration

enable_kernel_modules() {
    OUT_INFO "启用 TLS 和 nf_conntrack 内核模块"
    
    [[ "$(cat /etc/modules | grep tls)" = '' ]] && echo tls >> /etc/modules
    [[ "$(cat /etc/modules | grep nf_conntrack)" = '' ]] && echo nf_conntrack >> /etc/modules
    
    OUT_SUCCESS "内核模块配置完成"
}

# System Limit Adjustment

adjust_system_limits() {
    OUT_INFO "调整系统资源限制"
    
    cat <<'EOF' > /etc/security/limits.conf
# System Resource Limit Configuration
* soft nofile unlimited
* hard nofile unlimited
* soft nproc unlimited
* hard nproc unlimited
root soft nofile unlimited
root hard nofile unlimited
root soft nproc unlimited
root hard nproc unlimited
EOF

    cat <<'EOF' > /etc/systemd/system.conf
[Manager]
DefaultCPUAccounting=yes
DefaultIOAccounting=yes
DefaultIPAccounting=yes
DefaultMemoryAccounting=yes
DefaultTasksAccounting=yes
DefaultLimitCORE=infinity
DefaultLimitNPROC=infinity
DefaultLimitNOFILE=infinity
EOF

    OUT_SUCCESS "系统限制调整完成"
}

# Journald Log Configuration

configure_journald() {
    OUT_INFO "配置 journald 日志系统"
    
    cat > /etc/systemd/journald.conf <<EOF
[Journal]
Compress=yes
SystemMaxUse=512M
SystemMaxFileSize=128M
SystemMaxFiles=3
RuntimeMaxUse=256M
RuntimeMaxFileSize=64M
RuntimeMaxFiles=3
MaxRetentionSec=86400
MaxFileSec=259200
ForwardToSyslog=no
EOF

    OUT_SUCCESS "Journald 配置完成"
}

# Main Function

main() {
    OUT_ALERT "开始通用系统性能优化..."
    
    # Detect operating system
    detect_os
    
    # Execute various optimizations
    setup_time_sync
    optimize_random_generator
    optimize_ksm
    disable_hugepages
    optimize_kernel_params
    enable_kernel_modules
    adjust_system_limits
    configure_journald
    
    OUT_SUCCESS "通用系统性能优化完成！"
    OUT_INFO "建议重启系统以确保所有配置生效"
}

# Script Entry Point

    # Check if running as root
if [[ $EUID -ne 0 ]]; then
    OUT_ERROR "此脚本需要 root 权限运行"
    exit 1
fi

    # Execute main function
main

exit 0
