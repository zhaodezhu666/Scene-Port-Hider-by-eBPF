#!/system/bin/sh
# 红米 K Pad / KernelSU / eBPF 端口隐藏模块 —— 设备能力体检
# 只读采集，不修改任何系统状态。用法：adb shell su -c 'sh /data/local/tmp/hideport_check.sh'

SEP="=========================================="

echo "$SEP"
echo "[1] 设备与内核身份"
echo "$SEP"
echo "model          : $(getprop ro.product.model)"
echo "device         : $(getprop ro.product.device)"
echo "manufacturer   : $(getprop ro.product.manufacturer)"
echo "brand          : $(getprop ro.product.brand)"
echo "android ver    : $(getprop ro.build.version.release) (SDK $(getprop ro.build.version.sdk))"
echo "build id       : $(getprop ro.build.display.id)"
echo "security patch : $(getprop ro.build.version.security_patch)"
echo "abi            : $(getprop ro.product.cpu.abi)"
echo "abi list       : $(getprop ro.product.cpu.abilist)"
echo "kernel release : $(uname -r)"
echo "kernel version : $(uname -v)"
echo "uname -a       : $(uname -a)"
echo "hardware       : $(uname -m)"

echo
echo "$SEP"
echo "[2] KernelSU / root 环境"
echo "$SEP"
echo "ksud path      : $(command -v ksud 2>/dev/null || echo '(not found)')"
if [ -d /data/adb/ksu ]; then
    echo "ksu dir        : /data/adb/ksu"
    ls -1 /data/adb/ksu 2>/dev/null | sed 's/^/  - /'
fi
if [ -f /data/adb/ksu/.version ]; then
    echo "ksu version    : $(cat /data/adb/ksu/.version 2>/dev/null)"
fi
echo "magisk present : $([ -d /data/adb/magisk ] && echo yes || echo no)"
echo "apatch present : $([ -d /data/adb/apatch ] && echo yes || echo no)"
echo "su binary      : $(command -v su 2>/dev/null || echo '(none)')"
echo "euid           : $(id -u 2>/dev/null) / $(id -un 2>/dev/null)"
echo "uid now        : $(id -u 2>/dev/null)"

echo
echo "$SEP"
echo "[3] BTF 可用性（决定能否构建 CO-RE 程序）"
echo "$SEP"
if [ -r /sys/kernel/btf/vmlinux ]; then
    echo "BTF file       : /sys/kernel/btf/vmlinux 存在"
    echo "BTF size       : $(stat -c %s /sys/kernel/btf/vmlinux 2>/dev/null) bytes"
    echo "BTF sha256     : $(sha256sum /sys/kernel/btf/vmlinux 2>/dev/null | cut -d' ' -f1)"
    echo "BTF magic      : $(dd if=/sys/kernel/btf/vmlinux bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n') (期望 9feb0100)"
else
    echo "!! BTF file     : /sys/kernel/btf/vmlinux 不存在或不可读"
    echo "!! 结论：无法生成 vmlinux.h，该设备不支持本模块的构建路线"
fi

echo
echo "$SEP"
echo "[4] cgroup 布局（决定 connect4/bind4 能否挂载）"
echo "$SEP"
echo "--- mount | grep cgroup ---"
mount 2>/dev/null | grep -i cgroup
echo "--- /sys/fs/cgroup 类型 ---"
if [ -r /sys/fs/cgroup/cgroup.controllers ]; then
    echo "/sys/fs/cgroup 是 cgroup v2 (unified)"
    echo "controllers    : $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)"
    echo "subtree_control: $(cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null)"
elif [ -r /sys/fs/cgroup/cpu/cgroup.controllers ]; then
    echo "/sys/fs/cgroup 是 cgroup v1 (legacy) + v2 混合"
else
    echo "无法判定 cgroup 版本"
fi
echo "--- /sys/fs/cgroup 顶层条目 ---"
ls -1 /sys/fs/cgroup 2>/dev/null | head -30

echo
echo "$SEP"
echo "[5] kprobe 可挂载符号（决定 bind/getsockname/close 能否探针）"
echo "$SEP"
for sym in __sys_bind __arm64_sys_bind __se_sys_bind sys_bind SyS_bind \
           __sys_getsockname __arm64_sys_getsockname __se_sys_getsockname \
           __sys_close __arm64_sys_close __se_sys_close sys_close \
           __sys_connect __arm64_sys_connect; do
    hit=$(grep -c " $sym\$" /proc/kallsyms 2>/dev/null)
    if [ "$hit" != "0" ] && [ -n "$hit" ]; then
        echo "OK       $sym"
    fi
done

echo
echo "$SEP"
echo "[6] eBPF / BPF 能力"
echo "$SEP"
echo "bpf syscall    : $([ -e /proc/sys/kernel/unprivileged_bpf_disabled ] && echo present || echo absent)"
echo "unpriv_bpf_off : $(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)"
echo "bpf fs         : $(mount | grep -c 'bpf ' ) 个 bpf 挂载点"
mount 2>/dev/null | grep ' type bpf ' | head -10
echo "cgroup.controllers bpffs 检查:"
for p in /sys/fs/bpf /sys/fs/bpf/tc /sys/kernel/debug/tracing; do
    echo "  $p -> $([ -e "$p" ] && echo exists || echo missing)"
done

echo
echo "$SEP"
echo "[7] Scene 目标与端口占用"
echo "$SEP"
echo "--- Scene 包---"
pm list packages 2>/dev/null | grep -i -E "omarea|vtools|scene"
echo "--- Scene UID ---"
dumpsys package com.omarea.vtools 2>/dev/null | grep -m3 -E "userId=|appId=" || echo "Scene 未安装或无 dumpsys 权限"
echo "--- 监听端口 (Scene 相关) ---"
ss -ltnp 2>/dev/null | grep -E ":(8788|8765|14731|14754)\b" || echo "未发现 Scene 端口监听"
echo "--- 全部 147xx/87xx 监听 ---"
ss -ltn 2>/dev/null | grep -E ":(87[0-9]{2}|147[0-9]{2})\b" | head -20

echo
echo "$SEP"
echo "[8] SELinux / 执行环境"
echo "$SEP"
echo "selinux        : $(getenforce 2>/dev/null)"
echo "domain         : $(cat /proc/self/attr/current 2>/dev/null)"
echo "caps           : $(grep Cap /proc/self/status 2>/dev/null)"
echo "--- /proc/net/tcp 可读性（普通应用视角） ---"
echo "root 可读      : $(head -c 1 /proc/net/tcp >/dev/null 2>&1 && echo yes || echo no)"

echo
echo "$SEP"
echo "[9] 已有同名模块/脚本（防冲突）"
echo "$SEP"
ls -1 /data/adb/modules/ 2>/dev/null
echo "--- iptables 里是否已有隐藏端口规则 ---"
iptables -S OUTPUT 2>/dev/null | grep -E "8765|8788|14731|14754" || echo "无"
ip6tables -S OUTPUT 2>/dev/null | grep -E "8765|8788|14731|14754" || echo "无"

echo
echo "$SEP"
echo "体检结束"
echo "$SEP"
