#!/usr/bin/env python3
"""
susfs_manual_fix.py
Manual patch applicator untuk known rejects SUSFS di kernel sweet (sm6150/SDM732).

Fix:
  A) kernel/sys.c      — inject susfs_spoof_uname() ke SYSCALL_DEFINE1(newuname)
  B) fs/proc/task_mmu.c — inject label bypass_orig_flow yang gagal di hunk #5
  C) Verify/inject susfs.h include ke semua .c yang punya susfs calls
"""

import sys, os, re

# ── Fix A: kernel/sys.c ──────────────────────────────────────────────────────
print("Fixing kernel/sys.c ...")
with open("kernel/sys.c", "r") as f:
    data = f.read()

if "susfs_spoof_uname" not in data:
    anchor = "\tdown_read(&uts_sem);\n\tmemcpy(&tmp, utsname(), sizeof(tmp));\n\tup_read(&uts_sem);"
    replacement = (
        "\tdown_read(&uts_sem);\n"
        "\tmemcpy(&tmp, utsname(), sizeof(tmp));\n"
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
        "\tsusfs_spoof_uname(&tmp);\n"
        "#endif\n"
        "\tup_read(&uts_sem);"
    )
    extern_anchor = "SYSCALL_DEFINE1(newuname,"
    extern_inject = (
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
        "extern void susfs_spoof_uname(struct new_utsname* tmp);\n"
        "#endif\n"
        "SYSCALL_DEFINE1(newuname,"
    )
    if anchor in data:
        data = data.replace(extern_anchor, extern_inject, 1)
        data = data.replace(anchor, replacement, 1)
        with open("kernel/sys.c", "w") as f:
            f.write(data)
        print("  OK  kernel/sys.c patched")
    else:
        print("  WARN kernel/sys.c anchor not found — skipping")
else:
    print("  OK  kernel/sys.c already patched")

# ── Fix B: fs/proc/task_mmu.c — bypass_orig_flow label ──────────────────────
# Hunk #5 dari SUSFS patch gagal apply (offset terlalu jauh).
# Hunk itu menambahkan label `bypass_orig_flow:` setelah blok susfs_show_map_vma_spoofer.
# Hunk lain yang inject `goto bypass_orig_flow;` berhasil masuk → compile error.
#
# Dari patch original, struktur yang diinject:
#   if (susfs_show_map_vma_spoofer(m, vma))
#       goto bypass_orig_flow;
#   ... (kode original) ...
#   bypass_orig_flow:    <- label ini yang gagal
#
# Kita cari `goto bypass_orig_flow;` lalu trace ke akhir blok if/for yang sama,
# kemudian inject label di sana.
print("Fixing fs/proc/task_mmu.c ...")
with open("fs/proc/task_mmu.c", "r") as f:
    data = f.read()

if "bypass_orig_flow" in data and "bypass_orig_flow:" not in data:
    # Cari posisi goto
    goto_idx = data.find("goto bypass_orig_flow;")
    if goto_idx == -1:
        print("  WARN goto bypass_orig_flow not found")
    else:
        # Cari akhir dari blok/statement setelah goto — yaitu `show_map_vma_end:` label
        # atau closing brace dari fungsi show_smaps_rollup / show_map_vma
        # Anchor yang paling aman: cari `show_map_vma_end:` atau akhir scope terdekat
        # Dari patch: label ditempatkan tepat sebelum `show_map_vma_end:` atau sebelum
        # baris `m_start(m, pos)` atau sebelum closing brace fungsi
        #
        # Strategi: cari anchor terdekat setelah goto yang merupakan label atau closing scope
        search_region = data[goto_idx:]

        # Anchor kandidat — cari yang mana yang ada
        candidates = [
            "\nshow_map_vma_end:",          # label eksisting di fungsi
            "\n\trelease_task(task);",       # statement khas di akhir fungsi
            "\n\tput_task_struct(task);",
            "\n\ttask_unlock(task);",
            "\n\treturn 0;\n}",              # return terakhir di fungsi
        ]

        inject_before = None
        inject_pos = None
        for cand in candidates:
            idx = search_region.find(cand)
            if idx != -1:
                inject_before = cand
                inject_pos = goto_idx + idx
                break

        if inject_pos is not None:
            label_code = "\nbypass_orig_flow:\n"
            data = data[:inject_pos] + label_code + data[inject_pos:]
            with open("fs/proc/task_mmu.c", "w") as f:
                f.write(data)
            print(f"  OK  fs/proc/task_mmu.c: bypass_orig_flow label injected before '{inject_before.strip()}'")
        else:
            # Fallback: inject tepat setelah goto statement + satu baris
            # Ini less precise tapi compile akan OK
            lines = data.split("\n")
            for i, line in enumerate(lines):
                if "goto bypass_orig_flow;" in line:
                    # Cari akhir blok — scan maju sampai indentasi kembali ke level yang sama
                    base_indent = len(line) - len(line.lstrip())
                    for j in range(i + 1, min(i + 200, len(lines))):
                        stripped = lines[j].strip()
                        curr_indent = len(lines[j]) - len(lines[j].lstrip()) if lines[j].strip() else base_indent + 1
                        if stripped and curr_indent <= base_indent and not stripped.startswith("//"):
                            lines.insert(j, "bypass_orig_flow:")
                            print(f"  OK  fs/proc/task_mmu.c: bypass_orig_flow injected at line {j} (fallback)")
                            break
                    break
            data = "\n".join(lines)
            with open("fs/proc/task_mmu.c", "w") as f:
                f.write(data)
elif "bypass_orig_flow:" in data:
    print("  OK  fs/proc/task_mmu.c already has bypass_orig_flow label")
elif "bypass_orig_flow" not in data:
    print("  OK  fs/proc/task_mmu.c no bypass_orig_flow reference (patch may not have applied)")

# ── Fix C: scan semua .c yang punya susfs calls tapi belum include susfs.h ───
print("\nScanning for missing susfs.h includes ...")

INCLUDE_ANCHORS = [
    "#include <linux/fs.h>",
    "#include <linux/file.h>",
    "#include <linux/fdtable.h>",
    "#include <linux/namei.h>",
    "#include <linux/kernel.h>",
    "#include <linux/slab.h>",
    "#include <linux/mm.h>",
]

def inject_susfs_include(fpath):
    with open(fpath, "r", errors="replace") as f:
        content = f.read()
    if "#include <linux/susfs.h>" in content:
        return "already"
    for anchor in INCLUDE_ANCHORS:
        if anchor in content:
            content = content.replace(anchor, anchor + "\n#include <linux/susfs.h>", 1)
            with open(fpath, "w") as f:
                f.write(content)
            return f"injected after '{anchor}'"
    # Fallback: setelah include terakhir
    lines = content.split("\n")
    last_inc = max((i for i, l in enumerate(lines) if l.startswith("#include ")), default=None)
    if last_inc is not None:
        lines.insert(last_inc + 1, "#include <linux/susfs.h>")
        with open(fpath, "w") as f:
            f.write("\n".join(lines))
        return "injected (fallback after last include)"
    return "FAILED no anchor found"

found = False
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in ("susfs4ksu", "out", ".git")]
    for fname in files:
        if not fname.endswith(".c"):
            continue
        fpath = os.path.join(root, fname)
        try:
            with open(fpath, "r", errors="replace") as f:
                content = f.read()
        except Exception:
            continue
        if "#include <linux/susfs.h>" in content:
            continue
        calls = re.findall(r'\bsusfs_\w+\s*\(', content)
        if not calls:
            continue
        found = True
        result = inject_susfs_include(fpath)
        if "FAILED" in result:
            print(f"  ERR {fpath}: {result}")
            sys.exit(1)
        else:
            print(f"  OK  {fpath}: {result} (calls: {calls[:3]})")

if not found:
    print("  OK  No files need susfs.h injection")

print("\nManual fixes done.")
