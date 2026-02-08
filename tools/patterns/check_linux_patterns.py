import argparse
import os
import re
import struct


def parse_elf(path):
    with open(path, "rb") as f:
        data = f.read()

    if data[:4] != b"\x7fELF":
        raise ValueError(f"not an ELF file: {path}")

    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", data, 62)[0]

    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_size = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 32)[0]
    shstrtab = data[shstr_off : shstr_off + shstr_size]

    sections = []
    text = None
    text_addr = 0
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from("<I", data, off)[0]
        name = shstrtab[sh_name:].split(b"\x00")[0].decode("ascii", "ignore")
        sh_link = struct.unpack_from("<I", data, off + 40)[0]
        sh_entsize = struct.unpack_from("<Q", data, off + 56)[0]
        sh_addr = struct.unpack_from("<Q", data, off + 16)[0]
        sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
        sh_size = struct.unpack_from("<Q", data, off + 32)[0]

        sections.append({"name": name, "addr": sh_addr, "offset": sh_offset, "size": sh_size, "link": sh_link, "entsize": sh_entsize})
        if name == ".text":
            text = data[sh_offset : sh_offset + sh_size]
            text_addr = sh_addr

    if text is None:
        raise ValueError(f"no .text section found in: {path}")

    return {"data": data, "sections": sections, "text": text, "text_addr": text_addr}


def find_section_obj(sections, addr):
    for s in sections:
        if s["addr"] <= addr < s["addr"] + s["size"]:
            return s
    return None


def find_section(sections, addr):
    s = find_section_obj(sections, addr)
    return s["name"] if s else None


def parse_pat(s):
    tokens = s.strip().split()
    pb = []
    mask = []
    for t in tokens:
        if t == "?":
            pb.append(0)
            mask.append(False)
        else:
            pb.append(int(t, 16))
            mask.append(True)
    return bytes(pb), mask


def find_matches(text, pat_bytes, mask, max_matches=2):
    plen = len(pat_bytes)
    if plen == 0:
        return []

    first_fixed = -1
    for i, m in enumerate(mask):
        if m:
            first_fixed = i
            break
    if first_fixed == -1:
        return [0]

    fb = pat_bytes[first_fixed]
    out = []
    pos = 0
    while pos <= len(text) - plen:
        idx = text.find(bytes([fb]), pos + first_fixed)
        if idx == -1:
            break
        start = idx - first_fixed
        if start < 0 or start + plen > len(text):
            pos = idx + 1
            continue

        ok = True
        for j in range(plen):
            if mask[j] and text[start + j] != pat_bytes[j]:
                ok = False
                break
        if ok:
            out.append(start)
            if len(out) >= max_matches:
                break
        pos = start + 1
    return out


METHOD_TO_SO = {
    "addClientPatterns": "libclient.so",
    "addSceneSystemPatterns": "libscenesystem.so",
    "addTier0Patterns": "libtier0.so",
    "addFileSystemPatterns": "libfilesystem_stdio.so",
    "addSoundSystemPatterns": "libsoundsystem.so",
    "addPanoramaPatterns": "libpanorama.so",
}


def parse_pattern_types_sizes(pattern_types_dir):
    # Best-effort parser that extracts the final std::(u)intN_t in the STRONG_TYPE_ALIAS line,
    # while respecting WIN64_LINUX(..., linux_type) on mixed platform types.
    sizes = {}
    for fname in os.listdir(pattern_types_dir):
        if not fname.endswith("PatternTypes.h"):
            continue
        path = os.path.join(pattern_types_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                m = re.search(r"STRONG_TYPE_ALIAS\((\w+),", line)
                if not m:
                    continue
                name = m.group(1)

                size = None
                win = re.search(r"WIN64_LINUX\(([^,]+),\s*([^)]+)\)", line)
                if win:
                    t = win.group(2)
                    mm = re.search(r"std::u?int(\d+)_t", t)
                    if mm:
                        size = int(mm.group(1)) // 8

                if size is None:
                    mm_all = re.findall(r"std::u?int(\d+)_t", line)
                    if mm_all:
                        size = int(mm_all[-1]) // 8

                if size is not None:
                    sizes[name] = size
    return sizes


def parse_linux_patterns(linux_patterns_dir):
    patterns = []
    for fname in sorted(os.listdir(linux_patterns_dir)):
        if not fname.endswith("Linux.h"):
            continue

        path = os.path.join(linux_patterns_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            current_method = None
            for line in f:
                mm = re.search(r"(add\w+Patterns)\s*\(", line)
                if mm:
                    current_method = mm.group(1)

                pm = re.search(r'addPattern<([^,>]+)\s*,\s*CodePattern\{"([^"]+)"\}([^>]*)>', line)
                if not pm:
                    continue

                type_name = pm.group(1).strip()
                pat = pm.group(2).strip()
                ops = pm.group(3)

                add_offset = 0
                m_add = re.search(r"\.add\((\d+)\)", ops)
                if m_add:
                    add_offset = int(m_add.group(1))

                abs_next_len = None
                op = "none"
                m_abs = re.search(r"\.abs\((\d+)\)", ops)
                if m_abs:
                    abs_next_len = int(m_abs.group(1))
                    op = "abs"
                elif ".abs()" in ops:
                    abs_next_len = 4
                    op = "abs"
                if ".read()" in ops:
                    op = "read"
                    abs_next_len = None

                patterns.append(
                    {
                        "file": fname,
                        "path": path,
                        "method": current_method,
                        "type": type_name,
                        "pattern": pat,
                        "add": add_offset,
                        "op": op,
                        "abs_next_len": abs_next_len,
                    }
                )
    return patterns


def get_section_by_name(sections, name):
    for s in sections:
        if s["name"] == name:
            return s
    return None


def find_symbol_va(elf, symbol_name):
    data = elf["data"]
    sections = elf["sections"]

    sym_sec = get_section_by_name(sections, ".dynsym") or get_section_by_name(sections, ".symtab")
    if not sym_sec:
        return None

    link = sym_sec.get("link", 0)
    if link >= len(sections):
        return None
    str_sec = sections[link]

    entsize = sym_sec.get("entsize") or 24  # ELF64 Sym
    symtab = data[sym_sec["offset"] : sym_sec["offset"] + sym_sec["size"]]
    strtab = data[str_sec["offset"] : str_sec["offset"] + str_sec["size"]]

    for i in range(0, len(symtab) - entsize + 1, entsize):
        st_name = struct.unpack_from("<I", symtab, i)[0]
        st_shndx = struct.unpack_from("<H", symtab, i + 6)[0]
        st_value = struct.unpack_from("<Q", symtab, i + 8)[0]

        if st_name == 0:
            continue
        name = strtab[st_name:].split(b"\x00")[0].decode("utf-8", "ignore")
        if name != symbol_name:
            continue
        if st_shndx == 0:
            continue
        return st_value

    return None


def parse_panel_style_direct_pattern(linux_patterns_dir):
    path = os.path.join(linux_patterns_dir, "PanelStylePatternsLinux.h")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # patternFinders.panoramaPatternFinder("...pattern..."_pat).add(N).abs(M)
    m = re.search(r'panoramaPatternFinder\("([^"]+)"_pat\)([^;]+);', content)
    if not m:
        return None

    pat = m.group(1)
    ops = m.group(2)

    add_m = re.search(r"\.add\((\d+)\)", ops)
    abs_m = re.search(r"\.abs\((\d+)?\)", ops)
    if not add_m or not abs_m:
        return None

    abs_next_len = int(abs_m.group(1)) if abs_m.group(1) else 4
    return {"file": "PanelStylePatternsLinux.h", "path": path, "so": "libpanorama.so", "pattern": pat, "add": int(add_m.group(1)), "abs_next_len": abs_next_len}


def parse_sdl_direct_pattern_and_symbol(root, linux_patterns_dir):
    patterns_path = os.path.join(linux_patterns_dir, "SdlPatternsLinux.h")
    with open(patterns_path, "r", encoding="utf-8") as f:
        content = f.read()

    # patternFinders.sdlPatternFinder.matchPatternAtAddress((void*)peepEvents, "...pattern..."_pat).add(N).abs(...)
    m = re.search(r'matchPatternAtAddress\(\(void\*\)peepEvents,\s*"([^"]+)"_pat\)([^;]+);', content)
    if not m:
        return None

    pat = m.group(1)
    ops = m.group(2)

    add_m = re.search(r"\.add\((\d+)\)", ops)
    abs_m = re.search(r"\.abs\((\d+)?\)", ops)
    if not add_m or not abs_m:
        return None

    abs_next_len = int(abs_m.group(1)) if abs_m.group(1) else 4

    sdl_dll_path = os.path.join(root, "Source", "SDL", "SdlDll.h")
    symbol_name = "SDL_PeepEvents"
    try:
        with open(sdl_dll_path, "r", encoding="utf-8") as f:
            dll_content = f.read()
        mm = re.search(r'peepEvents\([^)]*\)\s*const[^{]*\{[^}]*getFunctionAddress\("([^"]+)"\)', dll_content, re.DOTALL)
        if mm:
            symbol_name = mm.group(1)
    except OSError:
        pass

    return {"file": "SdlPatternsLinux.h", "path": patterns_path, "so": "libSDL3.so.0", "symbol": symbol_name, "pattern": pat, "add": int(add_m.group(1)), "abs_next_len": abs_next_len}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    pattern_dir = os.path.join(root, "UP-To-DatePatterns")
    linux_patterns_dir = os.path.join(root, "Source", "MemoryPatterns", "Linux")
    pattern_types_dir = os.path.join(root, "Source", "MemoryPatterns", "PatternTypes")

    type_sizes = parse_pattern_types_sizes(pattern_types_dir)
    patterns = parse_linux_patterns(linux_patterns_dir)

    so_cache = {}
    failures = []

    for p in patterns:
        so_name = METHOD_TO_SO.get(p["method"])
        p["so"] = so_name
        if not so_name:
            failures.append(f"{p['file']}:{p['type']} unknown_method={p['method']}")
            continue

        if so_name not in so_cache:
            so_path = os.path.join(pattern_dir, so_name)
            so_cache[so_name] = parse_elf(so_path)

        so = so_cache[so_name]
        text = so["text"]

        pb, mask = parse_pat(p["pattern"])
        matches = find_matches(text, pb, mask, max_matches=2)
        if len(matches) != 1:
            failures.append(f"{p['file']}:{p['type']} matches={len(matches)}")
            continue

        start = matches[0]
        if p["add"] >= len(pb):
            failures.append(f"{p['file']}:{p['type']} add_out_of_range")
            continue

        if p["op"] == "abs":
            if p["add"] + 4 > len(pb):
                failures.append(f"{p['file']}:{p['type']} abs_disp_oob")
                continue

            disp = struct.unpack_from("<i", text, start + p["add"])[0]
            instr_addr = so["text_addr"] + start + p["add"]
            next_len = p.get("abs_next_len") or 4
            target = instr_addr + next_len + disp
            sec = find_section(so["sections"], target)
            if sec is None:
                failures.append(f"{p['file']}:{p['type']} abs_target_unmapped")
                continue

        if p["op"] == "read":
            size = type_sizes.get(p["type"], 4)
            if p["add"] + size > len(pb):
                failures.append(f"{p['file']}:{p['type']} read_oob")
                continue

    # Validate patterns that are not part of the PatternPool (BytePatternLiteral / matchPatternAtAddress).
    panel_style = parse_panel_style_direct_pattern(linux_patterns_dir)
    if panel_style:
        so_name = panel_style["so"]
        if so_name not in so_cache:
            so_cache[so_name] = parse_elf(os.path.join(pattern_dir, so_name))

        so = so_cache[so_name]
        pb, mask = parse_pat(panel_style["pattern"])
        matches = find_matches(so["text"], pb, mask, max_matches=2)
        if len(matches) != 1:
            failures.append(f"{panel_style['file']}:PanelStylePatterns::stylePropertiesSymbols matches={len(matches)}")
        else:
            start = matches[0]
            if panel_style["add"] + 4 > len(pb):
                failures.append(f"{panel_style['file']}:PanelStylePatterns::stylePropertiesSymbols abs_disp_oob")
            else:
                disp = struct.unpack_from("<i", so["text"], start + panel_style["add"])[0]
                instr_addr = so["text_addr"] + start + panel_style["add"]
                target = instr_addr + panel_style["abs_next_len"] + disp
                if find_section(so["sections"], target) is None:
                    failures.append(f"{panel_style['file']}:PanelStylePatterns::stylePropertiesSymbols abs_target_unmapped")
    else:
        failures.append("PanelStylePatternsLinux.h:PanelStylePatterns::stylePropertiesSymbols parse_failed")

    sdl = parse_sdl_direct_pattern_and_symbol(root, linux_patterns_dir)
    if sdl:
        so_path = os.path.join(pattern_dir, sdl["so"])
        if not os.path.exists(so_path):
            failures.append(f"{sdl['file']}:SdlPatterns::peepEventsPointer missing_module={sdl['so']}")
        else:
            sdl_elf = parse_elf(so_path)
            va = find_symbol_va(sdl_elf, sdl["symbol"])
            if va is None:
                failures.append(f"{sdl['file']}:SdlPatterns::peepEventsPointer missing_symbol={sdl['symbol']}")
            else:
                sec = find_section_obj(sdl_elf["sections"], va)
                if sec is None:
                    failures.append(f"{sdl['file']}:SdlPatterns::peepEventsPointer symbol_section_unmapped")
                else:
                    file_off = sec["offset"] + (va - sec["addr"])
                    pb, mask = parse_pat(sdl["pattern"])
                    data = sdl_elf["data"][file_off : file_off + len(pb)]
                    if len(data) != len(pb):
                        failures.append(f"{sdl['file']}:SdlPatterns::peepEventsPointer pattern_oob")
                    else:
                        ok = True
                        for j in range(len(pb)):
                            if mask[j] and data[j] != pb[j]:
                                ok = False
                                break
                        if not ok:
                            failures.append(f"{sdl['file']}:SdlPatterns::peepEventsPointer pattern_mismatch")
                        else:
                            if sdl["add"] + 4 > len(pb):
                                failures.append(f"{sdl['file']}:SdlPatterns::peepEventsPointer abs_disp_oob")
                            else:
                                disp = struct.unpack_from("<i", data, sdl["add"])[0]
                                instr_addr = va + sdl["add"]
                                target = instr_addr + sdl["abs_next_len"] + disp
                                if find_section(sdl_elf["sections"], target) is None:
                                    failures.append(f"{sdl['file']}:SdlPatterns::peepEventsPointer abs_target_unmapped")
    else:
        failures.append("SdlPatternsLinux.h:SdlPatterns::peepEventsPointer parse_failed")

    if failures:
        print("FAIL")
        for f in failures:
            print(f)
        raise SystemExit(1)

    print("OK")


if __name__ == "__main__":
    main()
