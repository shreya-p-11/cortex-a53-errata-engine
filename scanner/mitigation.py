from scanner.mapping import is_code_address


def _symbol_at(section, address, prefix):
    return any(
        symbol["value"] == address and symbol["name"].startswith(prefix)
        for symbol in section.get("symbols", [])
    )


def _branch_target(ins):
    return ins.operands[0].imm if ins.operands else None


def find_843419_mitigation(md, section, insns, index):
    """Return a mitigated 843419 sequence only for known linker shapes."""
    from scanner.detector import is_branch, is_ins2_type, match_seq1, reg_effects, reg_key

    first = insns[index]
    if first.address % 0x1000 not in (0xFF8, 0xFFC):
        return None
    if not is_code_address(section, first.address):
        return None

    # Near targets are rewritten from ADRP to ADR and followed by a linker
    # branch veneer marked by a new code mapping symbol.
    if first.mnemonic == "adr":
        match = match_seq1(md, insns, index)
        if match and all(is_code_address(section, ins.address) for ins in match):
            end = index + len(match)
            section_end = section["addr"] + section.get("size", len(section["data"]))
            for branch in insns[end:end + 4]:
                if (is_branch(branch.mnemonic)
                        and branch.mnemonic == "b"
                        and is_code_address(section, branch.address)
                        and _symbol_at(section, branch.address, "$x")
                        and (_branch_target(branch) is not None
                             and _branch_target(branch) >= section_end)):
                    return match

    # Far targets replace the final dependent access with a branch to the
    # linker-generated e843419@... stub.
    if first.mnemonic != "adrp" or index + 2 >= len(insns):
        return None
    rn = reg_key(md, first.operands[0].reg)
    ins2 = insns[index + 1]
    branch = insns[index + 2]
    if (rn is None or not is_ins2_type(ins2)
                or not is_branch(branch.mnemonic) or branch.mnemonic != "b"
                or rn in reg_effects(md, ins2)[1]):
        return None
    target = _branch_target(branch)
    if (target is None or not is_code_address(section, ins2.address)
            or not is_code_address(section, branch.address)
            or not _symbol_at(section, target, "e843419@")):
        return None
    return insns[index:index + 3]