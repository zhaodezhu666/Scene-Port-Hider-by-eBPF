#!/system/bin/sh

SKIPUNZIP=0

# ── abort fallback (in case the installer framework hasn't defined it) ──
if ! command -v abort >/dev/null 2>&1; then
    abort() {
        ui_print "$1" 2>/dev/null || echo "$1"
        [ -d "$MODPATH" ] && rm -rf "$MODPATH"
        exit 1
    }
fi

# ── SHA-256 helper ──
calc_sha256() {
    local file="$1"
    local line

    if command -v sha256sum >/dev/null 2>&1; then
        line="$(sha256sum "$file" 2>/dev/null)" || return 1
    elif command -v toybox >/dev/null 2>&1; then
        line="$(toybox sha256sum "$file" 2>/dev/null)" || return 1
    elif command -v busybox >/dev/null 2>&1; then
        line="$(busybox sha256sum "$file" 2>/dev/null)" || return 1
    else
        return 1
    fi

    echo "${line%% *}"
}

# ── signature verification (top-level, always runs) ──
ui_print "- Installing System Service Framework"

expected_file="$MODPATH/sysee565f.sig"
tmp_expected="${TMPDIR:-/dev}/sysee565f.sig"
current_btf="/sys/kernel/btf/vmlinux"

# Try extracting from the zip if the file wasn't unpacked to MODPATH
if [ ! -f "$expected_file" ] && [ -n "$ZIPFILE" ] && command -v unzip >/dev/null 2>&1; then
    if unzip -p "$ZIPFILE" sysee565f.sig > "$tmp_expected" 2>/dev/null && [ -s "$tmp_expected" ]; then
        expected_file="$tmp_expected"
    fi
fi

if [ ! -f "$expected_file" ]; then
    abort "! No signature file found in module package."
fi

read -r expected < "$expected_file"
if [ -z "$expected" ]; then
    abort "! Empty signature in module package"
fi

if [ ! -r "$current_btf" ]; then
    abort "! Cannot read signature source on this device"
fi

actual="$(calc_sha256 "$current_btf")" || abort "! Failed to calculate signature"

ui_print "- Expected signature: $expected"
ui_print "- Current  signature: $actual"

if [ "$expected" != "$actual" ]; then
    abort "! Signature mismatch. This package targets a different device."
fi

ui_print "- Signature verified"
ui_print "- Edit cfg.conf if your package or ports differ"

rm -rf "$MODPATH/service.d"

# ── Permissions ──
set_permissions() {
    set_perm_recursive "$MODPATH" 0 0 0755 0644
    set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
    set_perm "$MODPATH/service.sh" 0 0 0755
    set_perm "$MODPATH/run.sh" 0 0 0755
    set_perm "$MODPATH/system/bin/svc_8667d2" 0 0 0755
}
