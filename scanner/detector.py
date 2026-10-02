from capstone import (Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_REG, CS_OP_MEM,
                      CS_AC_READ, CS_AC_WRITE)
from scanner.loader import load_code_sections
from scanner.mapping import is_code_address
from scanner.mitigation import find_843419_mitigation

PAGE = 0x1000
SEQ1_OFFSETS = (0xFF8, 0xFFC)

# Instruction 2 of sequence 1 may be any load/store EXCEPT load-pairs and SIMD structure loads
NOT_INS2 = ("ldp", "ldnp", "ldpsw", "ldxp", "ldaxp", "stxp", "stlxp",
            "ld1", "ld2", "ld3", "ld4", "st2", "st3", "st4")
BRANCH_EXACT = {"b", "bl", "br", "blr", "ret", "eret", "cbz", "cbnz", "tbz", "tbnz"}
BRANCH_PREFIX = ("b.", "bc.", "bra", "blra", "ret", "eret")

HINT1 = ("relink with --fix-cortex-a53-843419, or insert a NOP so more than two "
         "instructions separate the ADRP and the final load/store")
HINT2 = "remove the ADRP or place a NOP directly after it"
HINT_835769 = "insert a NOP between the memory instruction and multiply-accumulate"
MADD_64 = {"madd", "msub"}
MADD_LONG_64 = {"smaddl", "smsubl", "umaddl", "umsubl"}


def word(ins):
    return int.from_bytes(bytes(ins.bytes), "little")


def is_branch(mnemonic):
    return mnemonic in BRANCH_EXACT or mnemonic.startswith(BRANCH_PREFIX)


def is_ldst(ins):
    """Encoding group 'Loads and Stores'."""
    return (word(ins) & 0x0A000000) == 0x08000000


def is_ins2_type(ins):
    return is_ldst(ins) and not ins.mnemonic.startswith(NOT_INS2)


def is_unsigned_imm(ins):
    """'Load/store register (unsigned immediate)' encoding class."""
    return (word(ins) & 0x3B000000) == 0x39000000


def reg_key(md, reg):
    """Normalise registers so w0 and x0 are the same register."""
    if not reg:
        return None
    name = md.reg_name(reg)
    if name is None or name in ("xzr", "wzr"):
        return None
    if name == "fp":
        return "r29"
    if name == "lr":
        return "r30"
    if name in ("sp", "wsp"):
        return "sp"
    if name[0] in "xw" and name[1:].isdigit():
        return "r" + name[1:]
    return name


def reg_effects(md, ins):
    """Return (registers read, registers written) by an instruction."""
    reads, writes = set(), set()
    for op in ins.operands:
        if op.type == CS_OP_REG:
            k = reg_key(md, op.reg)
            if k:
                if op.access & CS_AC_READ:
                    reads.add(k)
                if op.access & CS_AC_WRITE:
                    writes.add(k)
        elif op.type == CS_OP_MEM:
            for r in (op.mem.base, op.mem.index):
                k = reg_key(md, r)
                if k:
                    reads.add(k)
            if getattr(ins, "writeback", False):
                k = reg_key(md, op.mem.base)
                if k:
                    writes.add(k)
    return reads, writes


def mem_base(md, ins):
    for op in ins.operands:
        if op.type == CS_OP_MEM:
            return reg_key(md, op.mem.base)
    return None


def is_dependent_final(md, ins, rn):
    return is_unsigned_imm(ins) and mem_base(md, ins) == rn


def is_memory_instruction(ins):
    return any(op.type == CS_OP_MEM for op in ins.operands)


def is_835769_multiply_accumulate(ins):
    if ins.mnemonic not in MADD_64 | MADD_LONG_64:
        return False
    if ins.mnemonic in MADD_64 and not (word(ins) & (1 << 31)):
        return False
    accumulator = (word(ins) >> 10) & 0x1F
    return accumulator != 31


def match_seq1(md, insns, i):
    adrp = insns[i]
    if adrp.address % PAGE not in SEQ1_OFFSETS or i + 2 >= len(insns):
        return None
    rn = reg_key(md, adrp.operands[0].reg)
    if rn is None:
        return None
    ins2 = insns[i + 1]
    if not is_ins2_type(ins2) or rn in reg_effects(md, ins2)[1]:
        return None
    if is_dependent_final(md, insns[i + 2], rn):          # ADRP, ls, final
        return insns[i:i + 3]
    if i + 3 < len(insns):                                # ADRP, ls, other, final
        ins3 = insns[i + 2]
        if (not is_branch(ins3.mnemonic)
                and rn not in reg_effects(md, ins3)[1]
                and is_dependent_final(md, insns[i + 3], rn)):
            return insns[i:i + 4]
    return None


def match_seq2(md, insns, i):
    if i + 3 >= len(insns):
        return None
    a, b, c, d = insns[i:i + 4]
    rn = reg_key(md, a.operands[0].reg)
    if rn is None:
        return None
    reads_b, writes_b = reg_effects(md, b)
    if rn not in writes_b or rn in reads_b:
        return None
    if is_branch(b.mnemonic) or b.mnemonic == "adrp":
        return None
    if is_branch(c.mnemonic) or rn in reg_effects(md, c)[1]:
        return None
    if is_dependent_final(md, d, rn):
        return [a, b, c, d]
    return None


def detect_843419(path):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    findings = []
    for sec in load_code_sections(path):
        insns = list(md.disasm(sec["data"], sec["addr"]))
        for i, ins in enumerate(insns):
            mitigation = find_843419_mitigation(md, sec, insns, i)
            if mitigation:
                findings.append({
                    "errata_id": "843419",
                    "sequence": 1,
                    "address": ins.address,
                    "section": sec["name"],
                    "status": "MITIGATED",
                    "pattern": " ; ".join(
                        f"{matched.mnemonic} {matched.op_str}" for matched in mitigation
                    ),
                    "fix_hint": HINT1,
                })
                continue
            if ins.mnemonic != "adrp" or not is_code_address(sec, ins.address):
                continue
            for seq, matcher, hint in ((1, match_seq1, HINT1), (2, match_seq2, HINT2)):
                m = matcher(md, insns, i)
                if m and all(is_code_address(sec, matched.address) for matched in m):
                    findings.append({
                        "errata_id": "843419",
                        "sequence": seq,
                        "address": ins.address,
                        "section": sec["name"],
                        "status": "VULNERABLE",
                        "pattern": " ; ".join(f"{x.mnemonic} {x.op_str}" for x in m),
                        "fix_hint": hint,
                    })
    return findings


def detect_835769(path):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    findings = []
    for sec in load_code_sections(path):
        insns = list(md.disasm(sec["data"], sec["addr"]))
        for first, second in zip(insns, insns[1:]):
            if not is_memory_instruction(first) or not is_835769_multiply_accumulate(second):
                continue
            findings.append({
                "errata_id": "835769",
                "sequence": "sequence_1",
                "address": first.address,
                "section": sec["name"],
                "status": "VULNERABLE",
                "pattern": " ; ".join(
                    f"{ins.mnemonic} {ins.op_str}" for ins in (first, second)
                ),
                "fix_hint": HINT_835769,
            })
    return findings
