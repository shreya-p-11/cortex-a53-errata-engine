from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

from scanner.mapping import mapping_symbol_kind

SHF_EXECINSTR = 0x4  # flag marking executable sections


class ScanError(Exception):
    """A problem with the input that should be shown as a clean message."""


def _mapping_symbols(elf):
    symbols = {}
    for symbol_table in elf.iter_sections():
        if symbol_table["sh_type"] != "SHT_SYMTAB":
            continue
        for symbol in symbol_table.iter_symbols():
            kind = mapping_symbol_kind(symbol.name)
            if (kind is None or symbol["st_info"]["bind"] != "STB_LOCAL"
                    or symbol["st_info"]["type"] != "STT_NOTYPE"):
                continue
            section_index = symbol["st_shndx"]
            if not isinstance(section_index, int):
                continue
            section = elf.get_section(section_index)
            symbols.setdefault(section_index, []).append({
                "name": symbol.name,
                "value": symbol["st_value"],
                "address": symbol["st_value"],
                "section_index": section_index,
                "section": section.name if section is not None else None,
                "kind": kind,
            })
    return symbols


def load_code_sections(path, allow_relocatable=False):
    """Return every executable section of a linked AArch64 ELF as raw bytes."""
    sections = []
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            if elf["e_machine"] != "EM_AARCH64":
                raise ScanError("Not an AArch64 ELF file")
            if elf["e_type"] == "ET_REL" and not allow_relocatable:
                raise ScanError(
                    "This is an unlinked object file (.o). Errata depend on final "
                    "addresses, so link it into an ELF first."
                )
            mapping_symbols = _mapping_symbols(elf)
            for section_index, sec in enumerate(elf.iter_sections()):
                if sec["sh_type"] == "SHT_PROGBITS" and sec["sh_flags"] & SHF_EXECINSTR:
                    sections.append(
                        {
                            "name": sec.name,
                            "addr": sec["sh_addr"],
                            "size": sec["sh_size"],
                            "data": sec.data(),
                            "mapping_symbols": mapping_symbols.get(section_index, []),
                        }
                    )
    except FileNotFoundError:
        raise ScanError(f"File not found: {path}")
    except ELFError:
        raise ScanError(f"Not a valid ELF file: {path}")
    except OSError as e:
        raise ScanError(f"Cannot read {path}: {e}")
    if not sections:
        raise ScanError("No executable sections found in this ELF file")
    return sections