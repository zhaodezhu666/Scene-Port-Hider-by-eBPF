// SPDX-License-Identifier: GPL-2.0
//
// ARM64 Bionic requires executable PT_TLS alignment to be at least 64 bytes.
// Some static NDK links pull in an 8-byte-aligned TLS segment. This object
// contributes a real ELF TLS section with 64-byte alignment, forcing the final
// executable's PT_TLS p_align to 0x40.

    .section .tdata,"awT",%progbits
    .p2align 6
    .global svc_tls_align_anchor
    .type svc_tls_align_anchor, %object
svc_tls_align_anchor:
    .xword 0
    .size svc_tls_align_anchor, 8
