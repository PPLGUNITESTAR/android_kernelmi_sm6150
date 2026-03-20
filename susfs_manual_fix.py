#!/usr/bin/env python3
"""
susfs_manual_fix.py
Manual patch applicator untuk known rejects SUSFS di kernel sweet (sm6150/SDM732).
"""

import sys, os, re

# ── Fix A: kernel/sys.c ──────────────────────────────────────────────────────
# Dari .rej: patch inject extern decl + susfs_spoof_uname call ke newuname syscall
# Anchor tidak match karena indentasi di tree mungkin berbeda (tab vs spaces)
print("Fixing kernel/sys.c ...")
with open("kernel/sys.c", "r") as f:
    data = f.read()

if "susfs_spoof_uname" not in data:
    # Cari SYSCALL_DEFINE1(newuname dengan regex — tidak peduli indentasi
    # Inject extern decl tepat sebelumnya
    extern_decl = (
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
        "extern void susfs_spoof_uname(struct new_utsname* tmp);\n"
        "#endif\n"
    )
    call_inject = (
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
        "\tsusfs_spoof_uname(&tmp);\n"
        "#endif\n"
    )

    # Inject extern sebelum SYSCALL_DEFINE1(newuname
    if "SYSCALL_DEFINE1(newuname," in data:
        data = data.replace(
            "SYSCALL_DEFINE1(newuname,",
            extern_decl + "SYSCALL_DEFINE1(newuname,",
            1
        )
        print("  OK  extern decl injected")
    else:
        print("  ERR SYSCALL_DEFINE1(newuname not found")
        sys.exit(1)

    # Inject call setelah memcpy(&tmp, utsname(), sizeof(tmp));
    # Cari dengan regex untuk handle tab/space variation
    pattern = re.compile(
        r'([ \t]*memcpy\(&tmp,\s*utsname\(\),\s*sizeof\(tmp\)\);[ \t]*\n)',
        re.MULTILINE
    )
    m = pattern.search(data)
    if m:
        insert_pos = m.end()
        # Build indented call — ambil indent dari baris memcpy
        indent = re.match(r'^([ \t]*)', m.group(0)).group(1)
        call_lines = (
            f"{indent}#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
            f"{indent}susfs_spoof_uname(&tmp);\n"
            f"{indent}#endif\n"
        )
        data = data[:insert_pos] + call_lines + data[insert_pos:]
        with open("kernel/sys.c", "w") as f:
            f.write(data)
        print("  OK  kernel/sys.c susfs_spoof_uname call injected")
    else:
        print("  ERR memcpy(&tmp, utsname()) not found in newuname")
        sys.exit(1)
else:
    print("  OK  kernel/sys.c already patched")

# ── Fix B: fs/proc/task_mmu.c — bypass_orig_flow label ──────────────────────
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

    # Temukan scope fungsi yang mengandung goto_line pakai brace counting
    brace_depth = 0
    func_end = None
    for i in range(goto_line, len(lines)):
        brace_depth += lines[i].count('{') - lines[i].count('}')
        if brace_depth < 0:
            func_end = i
            break

    if func_end is not None and not (goto_line < label_line < func_end):
        print(f"  WARN label at line {label_line+1} outside function scope, fixing...")
        # Hapus label lama
        lines.pop(label_line)
        # Recalculate setelah pop
        goto_line2 = next(i for i, l in enumerate(lines) if "goto bypass_orig_flow;" in l)
        brace_depth = 0
        func_end2 = None
        for i in range(goto_line2, len(lines)):
            brace_depth += lines[i].count('{') - lines[i].count('}')
            if brace_depth < 0:
                func_end2 = i
                break
        if func_end2 is not None:
            lines.insert(func_end2, "bypass_orig_flow:")
            with open("fs/proc/task_mmu.c", "w") as f:
                f.write("\n".join(lines))
            print(f"  OK  label re-injected at line {func_end2+1}")
        else:
            print("  ERR cannot find function end")
            sys.exit(1)
    else:
        print(f"  OK  goto (line {goto_line+1}) and label (line {label_line+1}) in same function")
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
        lines.insert(func_end, "bypass_orig_flow:")
        with open("fs/proc/task_mmu.c", "w") as f:
            f.write("\n".join(lines))
        print(f"  OK  label injected before closing brace at line {func_end+1}")
    else:
        print("  ERR cannot find function end")
        sys.exit(1)

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
        fc = f.read()
    if "#include <linux/susfs.h>" in fc:
        return "already"
    for anchor in INCLUDE_ANCHORS:
        if anchor in fc:
            fc = fc.replace(anchor, anchor + "\n#include <linux/susfs.h>", 1)
            with open(fpath, "w") as f:
                f.write(fc)
            return f"injected after '{anchor}'"
    lines = fc.split("\n")
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
                fc = f.read()
        except Exception:
            continue
        if "#include <linux/susfs.h>" in fc:
            continue
        calls = re.findall(r'\bsusfs_\w+\s*\(', fc)
        if not calls:
            continue
        found = True
        result = inject_susfs_include(fpath)
        if "FAILED" in result:
            print(f"  ERR {fpath}: {result}")
            sys.exit(1)
        print(f"  OK  {fpath}: {result} (calls: {calls[:3]})")

if not found:
    print("  OK  No files need susfs.h injection")

print("\nManual fixes done.")
