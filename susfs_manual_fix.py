#!/usr/bin/env python3
"""
susfs_manual_fix.py
Manual patch applicator untuk known rejects SUSFS di kernel sweet (sm6150/SDM732).
Patch source: manipvlator/msm-sm6150-cafified (SUSFS v2.0.0)

Known rejects di tree sweet:
  A) kernel/sys.c        — susfs_spoof_uname hunk offset gagal
  B) fs/proc/cmdline.c   — susfs_spoof_cmdline hunk offset gagal
  C) fs/proc/task_mmu.c  — bypass_orig_flow label hunk offset gagal
  D) fs/namespace.c      — SUS_MOUNT hunk gagal (tidak kritikal, SUS_MOUNT=n)
  E) spot-check susfs.h includes untuk file yang terlewat
"""

import sys, os, re

# ── Fix A: kernel/sys.c ──────────────────────────────────────────────────────
print("Fixing kernel/sys.c ...")
with open("kernel/sys.c", "r") as f:
    data = f.read()

if "susfs_spoof_uname" not in data:
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

# ── Fix B: fs/proc/cmdline.c ─────────────────────────────────────────────────
# Patch inject susfs_spoof_cmdline_or_bootconfig() ke cmdline_proc_show()
# Hunk gagal karena offset. Inject manual.
print("Fixing fs/proc/cmdline.c ...")
with open("fs/proc/cmdline.c", "r") as f:
    data = f.read()

if "susfs_spoof_cmdline_or_bootconfig" not in data:
    # Patch mau inject di dalam cmdline_proc_show() setelah seq_puts/seq_putc
    # Pattern dari patch: inject setelah `seq_putc(m, '\n');` atau `seq_puts(m, ...)`
    # dan tambah include di atas

    # Step 1: inject include
    include_anchor = "#include <linux/fs.h>"
    if include_anchor in data and "#include <linux/susfs.h>" not in data:
        data = data.replace(
            include_anchor,
            include_anchor + "\n#include <linux/susfs.h>",
            1
        )

    # Step 2: inject call — cari seq_putc(m, '\n') di dalam fungsi cmdline_proc_show
    # Dari patch: susfs_spoof_cmdline_or_bootconfig dipanggil setelah seq_write/seq_puts
    # dan sebelum return 0
    pattern = re.compile(
        r'([ \t]*seq_putc\(m,\s*\'\\n\'\);[ \t]*\n)([ \t]*return 0;)',
        re.MULTILINE
    )
    m = pattern.search(data)
    if m:
        indent = re.match(r'^([ \t]*)', m.group(1)).group(1)
        inject = (
            f"{indent}#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
            f"{indent}susfs_spoof_cmdline_or_bootconfig(m);\n"
            f"{indent}#endif\n"
        )
        insert_pos = m.start(2)
        data = data[:insert_pos] + inject + data[insert_pos:]
        with open("fs/proc/cmdline.c", "w") as f:
            f.write(data)
        print("  OK  fs/proc/cmdline.c patched")
    else:
        # Fallback: cari return 0 di dalam fungsi show
        pattern2 = re.compile(r'([ \t]*return 0;\n)', re.MULTILINE)
        matches = list(pattern2.finditer(data))
        if matches:
            # Ambil match pertama (biasanya di cmdline_proc_show)
            m2 = matches[0]
            indent = re.match(r'^([ \t]*)', m2.group(1)).group(1)
            inject = (
                f"{indent}#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
                f"{indent}susfs_spoof_cmdline_or_bootconfig(m);\n"
                f"{indent}#endif\n"
            )
            data = data[:m2.start()] + inject + data[m2.start():]
            with open("fs/proc/cmdline.c", "w") as f:
                f.write(data)
            print("  OK  fs/proc/cmdline.c patched (fallback)")
        else:
            print("  WARN fs/proc/cmdline.c: anchor not found, skipping")
else:
    print("  OK  fs/proc/cmdline.c already patched")

# ── Fix C: fs/proc/task_mmu.c — bypass_orig_flow label ──────────────────────
print("Fixing fs/proc/task_mmu.c ...")
with open("fs/proc/task_mmu.c", "r") as f:
    content = f.read()

goto_present  = "goto bypass_orig_flow;" in content
label_present = "bypass_orig_flow:" in content

if not goto_present:
    print("  OK  no goto present, nothing to fix")
elif goto_present and label_present:
    lines = content.split("\n")
    goto_line  = next(i for i, l in enumerate(lines) if "goto bypass_orig_flow;" in l)
    label_line = next(i for i, l in enumerate(lines) if "bypass_orig_flow:" in l and "goto" not in l)

    # Cek apakah label dalam scope fungsi yang sama
    brace_depth = 0
    func_end = None
    for i in range(goto_line, len(lines)):
        brace_depth += lines[i].count('{') - lines[i].count('}')
        if brace_depth < 0:
            func_end = i
            break

    if func_end is not None and not (goto_line < label_line < func_end):
        print(f"  WARN label at line {label_line+1} outside function scope, re-injecting...")
        lines.pop(label_line)
        content_tmp = "\n".join(lines)
        lines = content_tmp.split("\n")
        goto_line2 = next(i for i, l in enumerate(lines) if "goto bypass_orig_flow;" in l)
        brace_depth = 0
        func_end2 = None
        for i in range(goto_line2, len(lines)):
            brace_depth += lines[i].count('{') - lines[i].count('}')
            if brace_depth < 0:
                func_end2 = i
                break
        if func_end2 is not None:
            # Inject label + null statement (;) untuk avoid C23 "label at end of compound statement"
            lines.insert(func_end2, "bypass_orig_flow: ;")
            with open("fs/proc/task_mmu.c", "w") as f:
                f.write("\n".join(lines))
            print(f"  OK  fs/proc/task_mmu.c label re-injected before line {func_end2+1}")
        else:
            print("  ERR cannot find function end")
            sys.exit(1)
    else:
        print(f"  OK  goto (line {goto_line+1}) and label (line {label_line+1}) in same function")
        # Cek apakah label punya null statement (avoid C23 warning → error)
        lines = content.split("\n")
        label_line2 = next(i for i, l in enumerate(lines) if "bypass_orig_flow:" in l and "goto" not in l)
        if lines[label_line2].strip() == "bypass_orig_flow:":
            lines[label_line2] = "bypass_orig_flow: ;"
            with open("fs/proc/task_mmu.c", "w") as f:
                f.write("\n".join(lines))
            print("  OK  fs/proc/task_mmu.c label null-statement added")
elif goto_present and not label_present:
    print("  Label missing, injecting...")
    lines = content.split("\n")
    goto_line = next(i for i, l in enumerate(lines) if "goto bypass_orig_flow;" in l)
    brace_depth = 0
    func_end = None
    for i in range(goto_line, len(lines)):
        brace_depth += lines[i].count('{') - lines[i].count('}')
        if brace_depth < 0:
            func_end = i
            break
    if func_end is not None:
        lines.insert(func_end, "bypass_orig_flow: ;")
        with open("fs/proc/task_mmu.c", "w") as f:
            f.write("\n".join(lines))
        print(f"  OK  label injected before closing brace at line {func_end+1}")
    else:
        print("  ERR cannot find function end")
        sys.exit(1)

# ── Fix C2: fs/proc/task_mmu.c — show_map_vma call site & missing functions ──
# Patch SUSFS mengubah show_map_vma signature jadi 3 args (tambah is_pid)
# Hunk #5 yang failed berisi: update call site + definisi __show_smap
# Perlu fix manual:
#   1. show_map_vma(m, vma) → show_map_vma(m, vma, 1)  di call site
#   2. __show_smap tidak ada di tree ini → ganti dengan show_smap
#   3. arch_pkeys_enabled / vma_pkey tidak ada → wrap dengan #ifdef
print("Fixing fs/proc/task_mmu.c call sites ...")
with open("fs/proc/task_mmu.c", "r") as f:
    tmu = f.read()

changed = False

# Fix 1: show_map_vma(m, vma) → show_map_vma(m, vma, 1)
# Hanya fix call site yang 2 argumen, bukan deklarasi fungsi itu sendiri
import re as _re
# Pattern: show_map_vma(m, vma) diikuti ; atau ) — tapi bukan deklarasi fungsi
tmu_new = _re.sub(
    r'show_map_vma\(m,\s*vma\)(?=\s*;)',
    'show_map_vma(m, vma, 1)',
    tmu
)
if tmu_new != tmu:
    print("  OK  show_map_vma call site updated to 3 args")
    tmu = tmu_new
    changed = True
else:
    print("  OK  show_map_vma call site already OK or not found")

# Fix 2: __show_smap → show_smap (fungsi ini tidak ada di tree, yang ada show_smap)
if "__show_smap" in tmu:
    tmu = tmu.replace("__show_smap(", "show_smap(")
    print("  OK  __show_smap → show_smap")
    changed = True
else:
    print("  OK  no __show_smap reference")

# Fix 3: arch_pkeys_enabled dan vma_pkey tidak ada di tree ini — guard dengan #ifdef
if "arch_pkeys_enabled()" in tmu and "#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS" not in tmu:
    pkey_block_old = "if (arch_pkeys_enabled())"
    pkey_block_new = "#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS\n\t\t\tif (arch_pkeys_enabled())"
    tmu = tmu.replace(pkey_block_old, pkey_block_new, 1)
    # Tambah #endif setelah seq_printf ProtectionKey
    tmu = _re.sub(
        r'(seq_printf\(m,\s*"ProtectionKey:[^;]+;)',
        r'\1\n\t\t\t#endif /* CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS */',
        tmu
    )
    print("  OK  arch_pkeys_enabled/vma_pkey wrapped with #ifdef")
    changed = True
else:
    print("  OK  no arch_pkeys_enabled issue")

if changed:
    with open("fs/proc/task_mmu.c", "w") as f:
        f.write(tmu)

# ── Fix D: fs/namespace.c — SUS_MOUNT hunk (tidak kritikal) ──────────────────
# Hunk #2 failed at 128 — ini inject susfs_alloc_unshare_ksu_vfsmnt ke mnt_alloc_group_id
# Tapi CONFIG_KSU_SUSFS_SUS_MOUNT=n di config kita, jadi tidak akan dicompile
# Cukup log saja, tidak perlu exit
print("Checking fs/namespace.c ...")
with open("fs/namespace.c", "r") as f:
    ns_data = f.read()
if "susfs_alloc_unshare_ksu_vfsmnt" not in ns_data and "CONFIG_KSU_SUSFS_SUS_MOUNT" in ns_data:
    print("  OK  fs/namespace.c SUS_MOUNT guarded, hunk reject non-critical (SUS_MOUNT=n)")
elif "susfs_alloc_unshare_ksu_vfsmnt" in ns_data:
    print("  OK  fs/namespace.c already has susfs_alloc_unshare_ksu_vfsmnt")
else:
    print("  OK  fs/namespace.c no SUS_MOUNT code (config disabled, safe to skip)")

# ── Fix E: spot-check susfs.h includes ───────────────────────────────────────
print("\nSpot-checking critical susfs.h includes ...")

CRITICAL_FILES = [
    ("fs/open.c",           "#include <linux/susfs.h>",     "#include <linux/fs.h>"),
    ("fs/namespace.c",      "#include <linux/susfs_def.h>", "#include <linux/task_work.h>"),
    ("fs/namei.c",          "#include <linux/susfs_def.h>", "#include <linux/uaccess.h>"),
    ("fs/proc/task_mmu.c",  "#include <linux/susfs.h>",     "#include <linux/slab.h>"),
    ("fs/stat.c",           "#include <linux/susfs.h>",     "#include <linux/fs.h>"),
    ("fs/proc/cmdline.c",   "#include <linux/susfs.h>",     "#include <linux/fs.h>"),
]

INCLUDE_ANCHORS = [
    "#include <linux/fs.h>",
    "#include <linux/file.h>",
    "#include <linux/task_work.h>",
    "#include <linux/uaccess.h>",
    "#include <linux/slab.h>",
    "#include <linux/kernel.h>",
    "#include <linux/seq_file.h>",
]

for fpath, needed_include, preferred_anchor in CRITICAL_FILES:
    if not os.path.exists(fpath):
        continue
    with open(fpath, "r", errors="replace") as f:
        fc = f.read()

    has_calls   = bool(re.search(r'\bsusfs_\w+\s*\(', fc))
    has_include = needed_include in fc

    if has_calls and not has_include:
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
        print(f"  OK  {fpath}: no susfs calls")

print("\nManual fixes done.")
