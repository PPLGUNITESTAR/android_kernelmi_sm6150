#!/usr/bin/env python3
import sys
import re
import logging
from pathlib import Path

# Konfigurasi Logging modern & deterministik
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

def backup_and_read(file_path: Path) -> str:
    """Membaca isi file dan membuat backup (.bak) secara atomik."""
    if not file_path.exists():
        log.error(f"File {file_path} tidak ditemukan!")
        sys.exit(1)
    
    content = file_path.read_text(encoding="utf-8", errors="replace")
    backup_path = file_path.with_suffix(file_path.suffix + ".bak")
    backup_path.write_text(content, encoding="utf-8")
    return content

def write_file(file_path: Path, content: str):
    """Menulis kembali isi file dengan aman."""
    file_path.write_text(content, encoding="utf-8")

def patch_sys_c(kernel_dir: Path):
    file_path = kernel_dir / "kernel/sys.c"
    log.info(f"Memeriksa {file_path} ...")
    data = backup_and_read(file_path)

    if "susfs_spoof_uname" in data:
        log.info("  -> OK (Sudah di-patch sebelumnya)")
        return

    # Injeksi Header KSU
    ksu_header = "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\nextern void susfs_spoof_uname(struct new_utsname* tmp);\n#endif\n"
    data = data.replace("SYSCALL_DEFINE1(newuname,", ksu_header + "SYSCALL_DEFINE1(newuname,", 1)

    # Injeksi Logika Uname menggunakan Regex yang toleran (*whitespace agnostic*)
    pattern = r"([ \t]*memcpy\(&tmp,\s*utsname\(\),\s*sizeof\(tmp\)\);[ \t]*\n)"
    match = re.search(pattern, data)
    if not match:
        log.error("  -> GAGAL: Anchor memcpy uname tidak ditemukan.")
        sys.exit(1)

    indent = re.match(r"^([ \t]*)", match.group(0)).group(1)
    injection = f"{indent}#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n{indent}susfs_spoof_uname(&tmp);\n{indent}#endif\n"
    data = data[:match.end()] + injection + data[match.end():]
    
    write_file(file_path, data)
    log.info("  -> SUCCESS: sys.c berhasil dimodifikasi.")

def patch_cmdline_c(kernel_dir: Path):
    file_path = kernel_dir / "fs/proc/cmdline.c"
    log.info(f"Memeriksa {file_path} ...")
    data = backup_and_read(file_path)

    if "susfs_spoof_cmdline_or_bootconfig" in data:
        log.info("  -> OK (Sudah di-patch sebelumnya)")
        return

    # Injeksi Include yang adaptif
    if "#include <linux/susfs.h>" not in data:
        for anchor in ["#include <linux/fs.h>", "#include <linux/seq_file.h>", "#include <linux/uaccess.h>"]:
            if anchor in data:
                data = data.replace(anchor, f"{anchor}\n#include <linux/susfs.h>", 1)
                break

    # Penempatan Logika pra-return menggunakan Regex Capture
    match = re.search(r"([ \t]*return 0;\n)", data)
    if match:
        indent = re.match(r"^([ \t]*)", match.group(1)).group(1)
        injection = f"{indent}#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n{indent}susfs_spoof_cmdline_or_bootconfig(m);\n{indent}#endif\n"
        data = data[:match.start()] + injection + data[match.start():]
        write_file(file_path, data)
        log.info("  -> SUCCESS: cmdline.c berhasil dimodifikasi.")
    else:
        log.warning("  -> WARNING: Anchor 'return 0;' tidak ditemukan di cmdline.c")

def patch_task_mmu_c(kernel_dir: Path):
    file_path = kernel_dir / "fs/proc/task_mmu.c"
    log.info(f"Memeriksa {file_path} ...")
    data = backup_and_read(file_path)

    # 1. Transmutasi argumen show_map_vma
    new_data = re.sub(r"show_map_vma\(m, vma\)(?=\s*;)", "show_map_vma(m, vma, 1)", data)
    if new_data != data:
        log.info("  -> OK: show_map_vma args diubah.")
        data = new_data

    # 2. Koreksi namespace show_smap
    if "__show_smap" in data:
        data = data.replace("__show_smap(", "show_smap(")
        log.info("  -> OK: __show_smap diubah menjadi show_smap.")

    # 3. Purgasi arsitektur x86 (pkeys) pada arm64
    if "arch_pkeys_enabled()" in data:
        data = re.sub(r'[ \t]*if \(arch_pkeys_enabled\(\)\)\s*\n[ \t]*seq_printf\([^;]+;\n', "", data)
        lines = [line for line in data.split("\n") if "arch_pkeys_enabled" not in line and "vma_pkey" not in line]
        data = "\n".join(lines)
        log.info("  -> OK: arch_pkeys_enabled (x86 logic) dihapus.")

    # 4. Injeksi bypass_orig_flow: dengan Lexical State Machine (AST Lexer Level)
    if "goto bypass_orig_flow;" in data and "bypass_orig_flow:" not in data:
        match_start = re.search(r"(static\s+int\s+show_smap\([^)]+\)\s*\{)", data)
        if match_start:
            start_idx = match_start.end()
            brace_count = 1
            i = start_idx
            
            # State variables for ignoring braces in strings and comments
            in_string = False
            in_char = False
            in_line_comment = False
            in_block_comment = False
            
            # Parsing Lexical: mengabaikan `}` jika ada di komentar atau string
            while i < len(data) and brace_count > 0:
                if in_line_comment:
                    if data[i] == '\n':
                        in_line_comment = False
                elif in_block_comment:
                    if data[i:i+2] == '*/':
                        in_block_comment = False
                        i += 1
                elif in_string:
                    if data[i] == '\\':
                        i += 1  # escape char
                    elif data[i] == '"':
                        in_string = False
                elif in_char:
                    if data[i] == '\\':
                        i += 1  # escape char
                    elif data[i] == "'":
                        in_char = False
                else:
                    if data[i:i+2] == '//':
                        in_line_comment = True
                    elif data[i:i+2] == '/*':
                        in_block_comment = True
                    elif data[i] == '"':
                        in_string = True
                    elif data[i] == "'":
                        in_char = True
                    elif data[i] == '{':
                        brace_count += 1
                    elif data[i] == '}':
                        brace_count -= 1
                i += 1
                
            if brace_count == 0:
                end_idx = i - 1  # Index absolut penutup fungsi '}'
                func_body = data[start_idx:end_idx]
                
                # Injeksi aman di pangkal exit point (return 0;)
                last_return_idx = func_body.rfind("return 0;")
                if last_return_idx != -1:
                    modified_body = (
                        func_body[:last_return_idx] + 
                        "bypass_orig_flow: ;\n\treturn 0;" + 
                        func_body[last_return_idx+9:]
                    )
                else:
                    modified_body = func_body + "\nbypass_orig_flow: ;\n"
                
                data = data[:start_idx] + modified_body + data[end_idx:]
                log.info("  -> SUCCESS: Label bypass_orig_flow disuntikkan secara deterministik dengan Lexer State Machine.")
            else:
                log.error("  -> CRITICAL: Brace imbalance terdeteksi di show_smap. File kernel korup secara sintaks.")
        else:
            log.warning("  -> WARNING: Deklarasi fungsi show_smap tidak ditemukan.")
    elif "bypass_orig_flow:" in data:
        log.info("  -> OK: Label bypass_orig_flow sudah ada.")

    write_file(file_path, data)

def spot_check_includes(kernel_dir: Path):
    log.info("Memeriksa integrasi struktural susfs.h ...")
    checks = [
        ("fs/open.c",          "#include <linux/susfs.h>", "#include <linux/fs.h>"),
        ("fs/stat.c",          "#include <linux/susfs.h>", "#include <linux/fs.h>"),
        ("fs/proc/task_mmu.c", "#include <linux/susfs.h>", "#include <linux/slab.h>"),
        ("fs/proc/cmdline.c",  "#include <linux/susfs.h>", "#include <linux/fs.h>"),
    ]
    for fp_str, need, pref in checks:
        fp = kernel_dir / fp_str
        if not fp.exists():
            continue
        
        fc = backup_and_read(fp)
        if re.search(r"\bsusfs_\w+\s*\(", fc) and need not in fc:
            for anc in [pref, "#include <linux/fs.h>", "#include <linux/file.h>", "#include <linux/slab.h>"]:
                if anc in fc:
                    fc = fc.replace(anc, f"{anc}\n{need}", 1)
                    write_file(fp, fc)
                    log.info(f"  -> SUCCESS {fp.name}: {need} disuntikkan secara implisit.")
                    break
        else:
            log.info(f"  -> OK {fp.name}: Tidak memerlukan re-injeksi.")

if __name__ == "__main__":
    # Orkestrasi dimulai secara relatif terhadap current working directory (CWD)
    root_dir = Path.cwd()
    log.info(f"Menginisialisasi SUSFS Vulnerability Patcher Engine di: {root_dir}")
    
    try:
        patch_sys_c(root_dir)
        patch_cmdline_c(root_dir)
        patch_task_mmu_c(root_dir)
        spot_check_includes(root_dir)
        log.info("Modifikasi C-Source Code dieksekusi secara paripurna dan stabil.")
    except Exception as e:
        log.critical(f"Terjadi interupsi level sistemik: {e}", exc_info=True)
        sys.exit(1)
