#!/system/bin/sh
# ============================================================================
# 红米 K Pad —— 从设备侧导出内核 BTF（无需 USB、无需电脑）
#
# 三条路径，任选其一。全部输出到 /storage/emulated/0/Download/vmlinux.btf
#
# 【路径 A】Termux（推荐，最省事）
#   1. F-Droid 安装 Termux
#   2. Termux 里执行：
#        pkg install -y termux-api  # 可选
#        su -c 'cp /sys/kernel/btf/vmlinux /storage/emulated/0/Download/vmlinux.btf'
#        chmod 0644 /storage/emulated/0/Download/vmlinux.btf
#        sha256sum /storage/emulated/0/Download/vmlinux.btf
#      把最后 sha256sum 的输出记下来，用来核对。
#
# 【路径 B】手机自带「文件管理」+ ADB over Wi-Fi（无需数据线）
#   1. 平板开「无线调试」：设置 → 更多设置 → 开发者选项 → 无线调试 → 打开
#   2. 记下无线调试主界面显示的「IP 地址和端口」
#   3. 电脑执行（adb 已装好）：
#        D:/WorkBuddyFiles/tools/platform-tools/adb.exe connect <IP:端口>
#      然后我就能远程拉取。
#
# 【路径 C】KernelSU 管理器内置终端
#   KernelSU 管理器 → 侧边栏/更多 → 终端，直接执行：
#        su -c 'cp /sys/kernel/btf/vmlinux /sdcard/Download/vmlinux.btf && chmod 0644 /sdcard/Download/vmlinux.btf'
#        sha256sum /sdcard/Download/vmlinux.btf
# ============================================================================

echo "=== 设备信息 ==="
getprop ro.product.model
getprop ro.product.device
getprop ro.build.version.release
uname -r
uname -m

echo
echo "=== BTF 检查 ==="
if [ -r /sys/kernel/btf/vmlinux ]; then
    echo "BTF 存在"
    echo "大小   : $(stat -c %s /sys/kernel/btf/vmlinux 2>/dev/null)"
    echo "SHA256 : $(sha256sum /sys/kernel/btf/vmlinux 2>/dev/null | cut -d' ' -f1)"
    echo "magic  : $(dd if=/sys/kernel/btf/vmlinux bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')  (期望 9feb0100)"
else
    echo "!! /sys/kernel/btf/vmlinux 不存在"
    echo "   该设备内核未导出 BTF，无法构建 CO-RE 程序"
fi

echo
echo "=== 导出 ==="
OUT=/storage/emulated/0/Download/vmlinux.btf
cp /sys/kernel/btf/vmlinux "$OUT" 2>/dev/null && chmod 0644 "$OUT" && {
    echo "已导出到 $OUT"
    ls -l "$OUT"
    echo "SHA256: $(sha256sum "$OUT" | cut -d' ' -f1)"
} || echo "!! 导出失败"

echo
echo "=== 兼容性关键项 ==="
echo "--- cgroup 版本（决定 connect4/bind4 能否挂载）---"
mount 2>/dev/null | grep -i cgroup
if [ -r /sys/fs/cgroup/cgroup.controllers ]; then
    echo "-> /sys/fs/cgroup 是 cgroup v2（unified），符合要求"
    echo "   controllers: $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)"
elif [ -r /sys/fs/cgroup/cpu/cgroup.controllers ]; then
    echo "-> /sys/fs/cgroup 是 cgroup v1 混合模式"
    echo "   注意：BPF_CGROUP_INET4_CONNECT 需要 cgroup v2，挂载可能失败"
else
    echo "-> 无法判定"
fi
echo "--- kprobe 符号 ---"
for s in __arm64_sys_bind __sys_bind __arm64_sys_getsockname __sys_getsockname __arm64_sys_close __sys_close; do
    grep -q " $s\$" /proc/kallsyms 2>/dev/null && echo "  OK  $s"
done
echo "--- KernelSU ---"
[ -d /data/adb/ksu ] && echo "  KernelSU 目录存在" || echo "  未见 /data/adb/ksu"
[ -f /data/adb/ksu/.version ] && echo "  版本: $(cat /data/adb/ksu/.version 2>/dev/null)"
echo "--- Scene 是否安装 ---"
pm list packages 2>/dev/null | grep -iE "omarea|vtools"
echo "--- Scene 端口监听 ---"
ss -ltn 2>/dev/null | grep -E ":(8788|8765|14731|14754)\b" || echo "  未发现监听（Scene 可能未运行）"
