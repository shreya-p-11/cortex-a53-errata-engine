from pathlib import Path
import yaml
from capstone import (CS_AC_READ, CS_AC_WRITE, CS_ARCH_ARM64, CS_MODE_ARM,
                      CS_OP_MEM, CS_OP_REG, Cs)
from scanner.loader import load_code_sections
from scanner.mapping import is_code_address

BRANCH_EXACT = {"b", "bl", "br", "blr", "ret", "eret", "cbz", "cbnz", "tbz", "tbnz"}
BRANCH_PREFIX = ("b.", "bc.", "bra", "blra", "ret", "eret")
SUPPORTED_STEP_KEYS = {
    "mnemonics", "mnemonics_not", "kind", "encoding", "branch",
    "address", "registers", "memory", "capture", "optional",
    "branch_target_outside", "symbol_prefix", "op_str"
}
SUPPORTED_KINDS = {"any", "load_store", "unsigned_immediate_load_store", "memory_operand"}

def load_rule(path):
    with Path(path).open(encoding="utf-8") as stream:
        rule = yaml.safe_load(stream) or {}
    if not isinstance(rule, dict) or "id" not in rule or "structural" not in rule:
        raise ValueError("Rule must contain id and structural fields")
    validate_rule(rule)
    return rule

def _validate_step(step):
    if not isinstance(step, dict):
        raise ValueError("Each rule step must be a mapping")
    unsupported = set(step) - SUPPORTED_STEP_KEYS
    if unsupported:
        raise ValueError(f"Unsupported step predicate(s): {', '.join(sorted(unsupported))}")
    if "kind" in step and step["kind"] not in SUPPORTED_KINDS:
        raise ValueError(f"Unknown instruction kind: {step['kind']}")
    for key in ("mnemonics", "mnemonics_not"):
        if key in step and (not isinstance(step[key], list)
                or not all(isinstance(value, str) for value in step[key])):
            raise ValueError(f"Rule step {key} must be a list of strings")
    if "optional" in step and not isinstance(step["optional"], bool):
        raise ValueError("Rule step optional must be boolean")
    if "branch" in step and not isinstance(step["branch"], bool):
        raise ValueError("Rule step branch must be boolean")
    encoding = step.get("encoding", {})
    if not isinstance(encoding, dict) or not isinstance(encoding.get("fields", []), list):
        raise ValueError("Rule step encoding.fields must be a list")
    for field in encoding.get("fields", []):
        if (not isinstance(field, dict) or not isinstance(field.get("bits"), list)
                or len(field["bits"]) != 2
                or not all(isinstance(value, int) for value in field["bits"])):
            raise ValueError("Encoding fields require two integer bit bounds")
        for key in ("equals", "not_equals"):
            if key in field and not isinstance(field[key], int):
                raise ValueError(f"Encoding field {key} must be an integer")

def validate_rule(rule):
    structural = rule.get("structural") if isinstance(rule, dict) else None
    if not isinstance(structural, dict):
        raise ValueError("Rule structural field must be a mapping")
    sequences = structural.get("sequences")
    if not isinstance(sequences, list) or not sequences:
        raise ValueError("Rule structural.sequences must be a non-empty list")
    if "scope" in structural and structural["scope"] not in ("code", None):
        raise ValueError("Unsupported structural scope")
    for sequence in sequences:
        if not isinstance(sequence, dict):
            raise ValueError("Each rule sequence must be a mapping")
        for required in ("name", "window", "steps", "fix_hint"):
            if required not in sequence:
                raise ValueError(f"Rule sequence is missing: {required}")
        window = sequence["window"]
        if (not isinstance(window, dict)
                or not isinstance(window.get("min"), int)
                or not isinstance(window.get("max"), int)
                or window["min"] < 1
                or window["min"] > window["max"]):
            raise ValueError("Rule sequence window must contain valid min/max integers")
        steps = sequence["steps"]
        if not isinstance(steps, list) or not steps:
            raise ValueError("Rule sequence steps must be a non-empty list")
        for step in steps:
            _validate_step(step)

    mitigation_structural = rule.get("mitigation_structural")
    if mitigation_structural:
        if not isinstance(mitigation_structural, dict):
            raise ValueError("Rule mitigation_structural field must be a mapping")
        m_sequences = mitigation_structural.get("sequences")
        if not isinstance(m_sequences, list) or not m_sequences:
            raise ValueError("Rule mitigation_structural.sequences must be a non-empty list")
        if "scope" in mitigation_structural and mitigation_structural["scope"] not in ("code", None):
            raise ValueError("Unsupported mitigation structural scope")
        for sequence in m_sequences:
            if not isinstance(sequence, dict):
                raise ValueError("Each mitigation sequence must be a mapping")
            for required in ("name", "window", "steps"):
                if required not in sequence:
                    raise ValueError(f"Mitigation sequence is missing: {required}")
            window = sequence["window"]
            if (not isinstance(window, dict)
                    or not isinstance(window.get("min"), int)
                    or not isinstance(window.get("max"), int)
                    or window["min"] < 1
                    or window["min"] > window["max"]):
                raise ValueError("Mitigation sequence window must contain valid min/max integers")
            steps = sequence["steps"]
            if not isinstance(steps, list) or not steps:
                raise ValueError("Mitigation sequence steps must be a non-empty list")
            for step in steps:
                _validate_step(step)

def _word(ins):
    return int.from_bytes(bytes(ins.bytes), "little")

def _is_branch(mnemonic):
    return mnemonic in BRANCH_EXACT or mnemonic.startswith(BRANCH_PREFIX)

def _is_load_store(ins):
    return (_word(ins) & 0x0A000000) == 0x08000000

def _is_unsigned_immediate_load_store(ins):
    return (_word(ins) & 0x3B000000) == 0x39000000

def _has_memory_operand(ins):
    return any(operand.type == CS_OP_MEM for operand in ins.operands)

def _encoding_matches(ins, encoding):
    instruction_word = _word(ins)
    for field in encoding.get("fields", []):
        if (field.get("when_mnemonics")
                and ins.mnemonic not in field["when_mnemonics"]):
            continue
        low, high = field["bits"]
        width = high - low + 1
        value = (instruction_word >> low) & ((1 << width) - 1)
        if "equals" in field and value != field["equals"]:
            return False
        if "not_equals" in field and value == field["not_equals"]:
            return False
    return True

def _register_key(md, reg):
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

def _register_effects(md, ins):
    reads, writes = set(), set()
    for operand in ins.operands:
        if operand.type == CS_OP_REG:
            register = _register_key(md, operand.reg)
            if register:
                if operand.access & CS_AC_READ:
                    reads.add(register)
                if operand.access & CS_AC_WRITE:
                    writes.add(register)
        elif operand.type == CS_OP_MEM:
            for register_id in (operand.mem.base, operand.mem.index):
                register = _register_key(md, register_id)
                if register:
                    reads.add(register)
            if getattr(ins, "writeback", False):
                register = _register_key(md, operand.mem.base)
                if register:
                    writes.add(register)
    return reads, writes

def _memory_base(md, ins):
    for operand in ins.operands:
        if operand.type == CS_OP_MEM:
            return _register_key(md, operand.mem.base)
    return None

def _resolve(value, captures):
    if isinstance(value, str) and value.startswith("$"):
        return captures.get(value[1:])
    return value

def _set_membership(registers, condition, captures):
    if condition is None:
        return True
    if isinstance(condition, list):
        expected = {_resolve(value, captures) for value in condition}
        return expected <= registers
    if "contains" in condition:
        return _resolve(condition["contains"], captures) in registers
    if "not_contains" in condition:
        return _resolve(condition["not_contains"], captures) not in registers
    return True

def _kind_matches(md, ins, kind):
    if kind is None or kind == "any":
        return True
    if kind == "load_store":
        return _is_load_store(ins)
    if kind == "unsigned_immediate_load_store":
        return _is_unsigned_immediate_load_store(ins)
    if kind == "memory_operand":
        return _has_memory_operand(ins)
    raise ValueError(f"Unknown instruction kind: {kind}")

def _symbol_at(section, address, prefix):
    """Check if a symbol with the given prefix exists at the address."""
    return any(
        symbol["value"] == address and symbol["name"].startswith(prefix)
        for symbol in section.get("symbols", [])
    )

def _step_matches(md, section, ins, step, captures):
    _validate_step(step)
    mnemonics = step.get("mnemonics")
    if mnemonics is not None and ins.mnemonic not in mnemonics:
        return None
    if ins.mnemonic in step.get("mnemonics_not", []):
        return None

    # Generic operand string matching (e.g., "cmvac", "cmvau")
    op_str = step.get("op_str")
    if op_str is not None:
        if isinstance(op_str, list):
            if not any(s in ins.op_str for s in op_str):
                return None
        elif op_str not in ins.op_str:
            return None

    if not _kind_matches(md, ins, step.get("kind")):
        return None
    if not _encoding_matches(ins, step.get("encoding", {})):
        return None
    if "branch" in step and _is_branch(ins.mnemonic) != step["branch"]:
        return None

    address = step.get("address", {})
    if "modulo" in address:
        offset = ins.address % address["modulo"]
        if offset not in address.get("one_of", [address.get("equals")]):
            return None

    if step.get("branch_target_outside"):
        if not ins.operands or not hasattr(ins.operands[0], 'imm'):
            return None
        target = ins.operands[0].imm
        section_end = section["addr"] + section.get("size", len(section["data"]))
        if target < section_end:
            return None

    if "symbol_prefix" in step:
        if not ins.operands or not hasattr(ins.operands[0], 'imm'):
            return None
        target = ins.operands[0].imm
        if not _symbol_at(section, target, step["symbol_prefix"]):
            return None

    effects = _register_effects(md, ins)
    registers = step.get("registers", {})
    if not _set_membership(effects[0], registers.get("reads"), captures):
        return None
    if not _set_membership(effects[1], registers.get("writes"), captures):
        return None

    memory = step.get("memory", {})
    if "base_equals" in memory:
        if _memory_base(md, ins) != _resolve(memory["base_equals"], captures):
            return None

    updated = dict(captures)
    capture = step.get("capture", {}).get("register")
    if capture:
        if capture["operand"] >= len(ins.operands):
            return None
        operand = ins.operands[capture["operand"]]
        if operand.type != CS_OP_REG:
            return None
        updated[capture["as"]] = _register_key(md, operand.reg)
        if updated[capture["as"]] is None:
            return None
    return updated

def match_sequence(md, section, insns, sequence):
    steps = sequence["steps"]
    window = sequence["window"]
    scope = sequence.get("scope")

    def match_from(step_index, instruction_index, captures, start_idx):
        if step_index == len(steps):
            consumed = instruction_index - start_idx
            if window["min"] <= consumed <= window["max"]:
                return instruction_index, captures
            return None
        step = steps[step_index]
        optional = step.get("optional", False)
        if optional:
            skipped = match_from(step_index + 1, instruction_index, captures, start_idx)
            if skipped:
                return skipped
        if instruction_index >= len(insns):
            return None
        ins = insns[instruction_index]
        if scope == "code" and not is_code_address(section, ins.address):
            return None
        updated = _step_matches(md, section, ins, step, captures)
        if updated is None:
            return None
        return match_from(step_index + 1, instruction_index + 1, updated, start_idx)

    for start in range(len(insns)):
        result = match_from(0, start, {}, start)
        if result:
            end, captures = result
            return insns[start:end], captures
    return None

def detect_rule(elf_path, rule):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    findings = []
    
    for section in load_code_sections(elf_path):
        insns = list(md.disasm(section["data"], section["addr"]))
        mitigated_addresses = set()
        
        # 1. Check for Mitigated Patterns
        if rule.mitigation_structural:
            for sequence in rule.mitigation_structural.get("sequences", []):
                for start, ins in enumerate(insns):
                    if rule.mitigation_structural.get("scope") == "code" and not is_code_address(section, ins.address):
                        continue
                    
                    match = match_sequence(md, section, insns[start:], sequence)
                    if match:
                        matched, _ = match
                        mitigated_addresses.add(matched[0].address)
                        findings.append({
                            "errata_id": rule.errata_id,
                            "sequence": sequence["name"],
                            "address": matched[0].address,
                            "section": section["name"],
                            "status": "MITIGATED",
                            "pattern": " ; ".join(f"{i.mnemonic} {i.op_str}" for i in matched),
                            "fix_hint": sequence.get("fix_hint", "Linker workaround detected; no action needed"),
                        })
                        break

        # 2. Check for Vulnerable Patterns
        for sequence in rule.structural.get("sequences", []):
            for start, ins in enumerate(insns):
                if rule.structural.get("scope") == "code" and not is_code_address(section, ins.address):
                    continue
                
                if ins.address in mitigated_addresses:
                    continue
                    
                match = match_sequence(md, section, insns[start:], sequence)
                if match:
                    matched, _ = match
                    findings.append({
                        "errata_id": rule.errata_id,
                        "sequence": sequence["name"],
                        "address": matched[0].address,
                        "section": section["name"],
                        "status": "VULNERABLE",
                        "pattern": " ; ".join(f"{i.mnemonic} {i.op_str}" for i in matched),
                        "fix_hint": sequence.get("fix_hint", ""),
                    })
                    break
                    
    return findings