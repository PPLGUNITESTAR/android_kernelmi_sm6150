#!/usr/bin/env python3
"""
susfs_manual_fix.py
Manual patch applicator untuk known rejects SUSFS di kernel sweet (sm6150/SDM732).

Patch source: manipvlator/msm-sm6150-cafified (SUSFS v2.0.0, sm6150 port)

Fix yang masih diperlukan:
  A) kernel/sys.c  — inject susfs_spoof_uname() jika hunk offset gagal
  B) Skip scan susfs.h — patch ini sudah inject include ke setiap file sendiri
"""

import sys, os, re

# ── Fix A: kernel/sys.c ──────────────────────────────────────────────────────
print("Fixing kernel/sys.c ...")
with open("kernel/sys.c", "r") as f:
    data = f.read()

if "susfs_spoof_uname" not in data:
    # Inject extern decl sebelum SYSCALL_DEFINE1(newuname
    extern_decl = (
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
        "extern void susfs_spoof_uname(struct new_utsname* tmp);\n"
        "#endif\n"
    )
    if "SYSCALL_DEFINE1(newuname," in data:
        data = data.replace(
            "SYSCALL_DEFINE1(newuname,",
            extern_decl + "SYSCALL_DEFINE1(newuname,",
            1
        )
    else:
        print("  ERR SYSCALL_DEFINE1(newuname not found")
        sys.exit(1)

    # Inject call setelah memcpy(&tmp, utsname(), sizeof(tmp)) dengan regex
    # supaya handle tab/space variation
    pattern = re.compile(
        r'([ \t]*memcpy\(&tmp,\s*utsname\(\),\s*sizeof\(tmp\)\);[ \t]*\n)',
        re.MULTILINE
    )
    m = pattern.search(data)
    if m:
        indent = re.match(r'^([ \t]*)', m.group(0)).group(1)
        call_lines = (
            f"{indent}#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
            f"{indent}susfs_spoof_uname(&tmp);\n"
            f"{indent}#endif\n"
        )
        data = data[:m.end()] + call_lines + data[m.end():]
        with open("kernel/sys.c", "w") as f:
            f.write(data)
        print("  OK  kernel/sys.c patched")
    else:
        print("  ERR memcpy(&tmp, utsname()) not found")
        sys.exit(1)
else:
    print("  OK  kernel/sys.c already patched")

# ── Fix B: drivers/input/input.c dan fs/exec.c ───────────────────────────────
# Patch ini inject KSU hooks ke input.c dan exec.c.
# Kalau kernel lo sudah punya hooks itu (KSU native di tree), hunk akan reversed.
# --batch --forward di step workflow sudah handle ini — tidak perlu fix manual.
print("Skipping input.c/exec.c check (handled by --batch --forward in workflow)")

# ── Fix C: scan susfs.h include ──────────────────────────────────────────────
# Patch manipvlator sudah inject include ke setiap file yang butuh.
# Hanya perlu fallback kalau ada file yang terlewat karena hunk offset.
print("\nSpot-checking critical susfs.h includes ...")

CRITICAL_FILES = [
    ("fs/open.c",           "#include <linux/susfs.h>", "#include <linux/fs.h>"),
    ("fs/namespace.c",      "#include <linux/susfs_def.h>", "#include <linux/task_work.h>"),
    ("fs/namei.c",          "#include <linux/susfs_def.h>", "#include <linux/uaccess.h>"),
    ("fs/proc/task_mmu.c",  "#include <linux/susfs.h>", "#include <linux/slab.h>"),
    ("fs/stat.c",           "#include <linux/susfs.h>", "#include <linux/fs.h>"),
]

INCLUDE_ANCHORS = [
    "#include <linux/fs.h>",
    "#include <linux/file.h>",
    "#include <linux/task_work.h>",
    "#include <linux/uaccess.h>",
    "#include <linux/slab.h>",
    "#include <linux/kernel.h>",
]

for fpath, needed_include, preferred_anchor in CRITICAL_FILES:
    if not os.path.exists(fpath):
        continue
    with open(fpath, "r", errors="replace") as f:
        fc = f.read()

    # Cek apakah ada susfs call tapi include belum masuk
    has_calls = bool(re.search(r'\bsusfs_\w+\s*\(', fc))
    has_include = needed_include in fc

    if has_calls and not has_include:
        # Inject
        injected = False
        for anchor in [preferred_anchor] + INCLUDE_ANCHORS:
            if anchor in fc:
                fc = fc.replace(anchor, anchor + f"\n{needed_include}", 1)
                with open(fpath, "w") as f:
                    f.write(fc)
                print(f"  OK  {fpath}: {needed_include} injected after '{anchor}'")
                injected = True
                break
        if not injected:
            print(f"  WARN {fpath}: could not inject {needed_include}")
    elif has_calls and has_include:
        print(f"  OK  {fpath}: include present")
    elif not has_calls:
        print(f"  OK  {fpath}: no susfs calls (patch may not have applied, skip)")

print("\nManual fixes done.")
