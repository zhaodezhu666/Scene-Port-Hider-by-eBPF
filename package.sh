#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZIP="${1:-$ROOT/../sysee565f.zip}"

if [[ ! -f "$ROOT/system/bin/svc_8667d2" ]]; then
    echo "Missing executable: $ROOT/system/bin/svc_8667d2" >&2
    echo "Run ./build.sh first." >&2
    exit 1
fi

fingerprint="$ROOT/sysee565f.sig"
btf_source=""
for candidate in "$ROOT/btf/vmlinux.btf" "$ROOT/vmlinux.btf"; do
    if [[ -f "$candidate" ]]; then
        btf_source="$candidate"
        break
    fi
done

if [[ -n "$btf_source" ]]; then
    sha256sum "$btf_source" | awk '{print $1}' > "$fingerprint"
    echo "Wrote kernel BTF fingerprint from $btf_source"
elif [[ -f "$fingerprint" ]]; then
    rm -f "$fingerprint"
    echo "Removed stale kernel BTF fingerprint"
else
    echo "Warning: no vmlinux.btf found; package will not enforce kernel BTF match." >&2
fi

(
    cd "$ROOT"
    files=(
        module.prop
        cfg.conf
        post-fs-data.sh
        service.sh
        run.sh
        customize.sh
        uninstall.sh
        system/bin/svc_8667d2
    )
    if [[ -f sysee565f.sig ]]; then
        files+=(sysee565f.sig)
    fi

    rm -f "$ZIP"
    zip -r "$ZIP" "${files[@]}" -x '*/.git/*'
)

echo "Wrote $ZIP"
