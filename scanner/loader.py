from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

SHF_EXECINSTR = 0x4  # flag marking executable sections


class ScanError(Exception):
    """A problem with the input that should be shown as a clean message."""


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
            for sec in elf.iter_sections():
                if sec["sh_type"] == "SHT_PROGBITS" and sec["sh_flags"] & SHF_EXECINSTR:
                    sections.append(
                        {"name": sec.name, "addr": sec["sh_addr"], "data": sec.data()}
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