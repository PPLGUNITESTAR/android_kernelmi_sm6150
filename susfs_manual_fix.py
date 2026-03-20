#!/usr/bin/env python3
import sys, os, re

# ── kernel/sys.c ─────────────────────────────────────────────────────────────
print("Fixing kernel/sys.c ...")
with open("kernel/sys.c", "r") as f:
    data = f.read()
if "susfs_spoof_uname" not in data:
    ed = "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\nextern void susfs_spoof_uname(struct new_utsname* tmp);\n#endif\n"
    data = data.replace("SYSCALL_DEFINE1(newuname,", ed + "SYSCALL_DEFINE1(newuname,", 1)
    m = re.search(r"([ \t]*memcpy\(&tmp,\s*utsname\(\),\s*sizeof\(tmp\)\);[ \t]*\n)", data)
    if m:
        ind = re.match(r"^([ \t]*)", m.group(0)).group(1)
        inj = ind+"#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"+ind+"susfs_spoof_uname(&tmp);\n"+ind+"#endif\n"
        data = data[:m.end()] + inj + data[m.end():]
        open("kernel/sys.c","w").write(data)
        print("  OK  sys.c patched")
    else:
        print("  ERR sys.c anchor not found"); sys.exit(1)
else:
    print("  OK  sys.c already patched")

# ── fs/proc/cmdline.c ─────────────────────────────────────────────────────────
print("Fixing fs/proc/cmdline.c ...")
with open("fs/proc/cmdline.c", "r") as f:
    data = f.read()
if "susfs_spoof_cmdline_or_bootconfig" not in data:
    if "#include <linux/susfs.h>" not in data:
        for anc in ["#include <linux/fs.h>","#include <linux/seq_file.h>","#include <linux/uaccess.h>"]:
            if anc in data:
                data = data.replace(anc, anc+"\n#include <linux/susfs.h>", 1); break
    m = re.search(r"([ \t]*return 0;\n)", data)
    if m:
        ind = re.match(r"^([ \t]*)", m.group(1)).group(1)
        inj = ind+"#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"+ind+"susfs_spoof_cmdline_or_bootconfig(m);\n"+ind+"#endif\n"
        data = data[:m.start()] + inj + data[m.start():]
        open("fs/proc/cmdline.c","w").write(data)
        print("  OK  cmdline.c patched")
    else:
        print("  WARN cmdline.c anchor not found")
else:
    print("  OK  cmdline.c already patched")

# ── fs/proc/task_mmu.c ────────────────────────────────────────────────────────
print("Fixing fs/proc/task_mmu.c ...")
with open("fs/proc/task_mmu.c", "r") as f:
    data = f.read()

# Fix show_map_vma(m, vma) -> show_map_vma(m, vma, 1)
d2 = re.sub(r"show_map_vma\(m, vma\)(?=\s*;)", "show_map_vma(m, vma, 1)", data)
if d2 != data:
    print("  OK  show_map_vma -> 3 args"); data = d2

# Fix __show_smap -> show_smap
if "__show_smap" in data:
    data = data.replace("__show_smap(", "show_smap(")
    print("  OK  __show_smap -> show_smap")

# Fix arch_pkeys_enabled / vma_pkey (x86-only, tidak ada di arm64)
if "arch_pkeys_enabled()" in data and "#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS" not in data:
    data = data.replace(
        "if (arch_pkeys_enabled())",
        "#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS\n\t\t\tif (arch_pkeys_enabled())"
    )
    data = re.sub(
        r'(seq_printf\(m, "ProtectionKey:[^;]+;)',
        r'\1\n\t\t\t#endif /* CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS */',
        data
    )
    print("  OK  arch_pkeys wrapped with #ifdef")

# Fix bypass_orig_flow label
lines = data.split("\n")
gotos  = [i for i,l in enumerate(lines) if "goto bypass_orig_flow;" in l]
labels = [i for i,l in enumerate(lines) if "bypass_orig_flow:" in l and "goto" not in l]

if gotos:
    gl = gotos[0]
    if labels:
        ll = labels[0]
        d=0; fe=None
        for i in range(gl, len(lines)):
            d += lines[i].count("{") - lines[i].count("}")
            if d < 0: fe=i; break
        if fe and not (gl < ll < fe):
            # Label di luar scope fungsi — hapus dan re-inject
            lines.pop(ll)
            gl2 = next(i for i,l in enumerate(lines) if "goto bypass_orig_flow;" in l)
            d2=0; fe2=None
            for i in range(gl2, len(lines)):
                d2 += lines[i].count("{") - lines[i].count("}")
                if d2 < 0: fe2=i; break
            if fe2:
                lines.insert(fe2, "bypass_orig_flow: ;")
                print("  OK  bypass_orig_flow label re-injected")
        elif lines[ll].strip() == "bypass_orig_flow:":
            # Label di fungsi benar tapi tidak ada null statement
            lines[ll] = "bypass_orig_flow: ;"
            print("  OK  bypass_orig_flow null stmt added")
        else:
            print("  OK  bypass_orig_flow already OK")
    else:
        # Label belum ada sama sekali
        d=0; fe=None
        for i in range(gl, len(lines)):
            d += lines[i].count("{") - lines[i].count("}")
            if d < 0: fe=i; break
        if fe:
            lines.insert(fe, "bypass_orig_flow: ;")
            print("  OK  bypass_orig_flow label injected")
else:
    print("  OK  no bypass_orig_flow goto found")

open("fs/proc/task_mmu.c","w").write("\n".join(lines))

# ── spot-check susfs.h includes ───────────────────────────────────────────────
print("\nChecking susfs.h includes ...")
checks = [
    ("fs/open.c",          "#include <linux/susfs.h>", "#include <linux/fs.h>"),
    ("fs/stat.c",          "#include <linux/susfs.h>", "#include <linux/fs.h>"),
    ("fs/proc/task_mmu.c", "#include <linux/susfs.h>", "#include <linux/slab.h>"),
    ("fs/proc/cmdline.c",  "#include <linux/susfs.h>", "#include <linux/fs.h>"),
]
for fp, need, pref in checks:
    if not os.path.exists(fp): continue
    fc = open(fp,"r",errors="replace").read()
    if re.search(r"\bsusfs_\w+\s*\(", fc) and need not in fc:
        for anc in [pref,"#include <linux/fs.h>","#include <linux/file.h>","#include <linux/slab.h>"]:
            if anc in fc:
                fc = fc.replace(anc, anc+"\n"+need, 1)
                open(fp,"w").write(fc)
                print(f"  OK  {fp}: {need} injected")
                break
    else:
        print(f"  OK  {fp}: OK")

print("\nManual fixes done.")