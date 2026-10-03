from dataclasses import dataclass
from pathlib import Path

import yaml

from scanner.detector import detect_835769, detect_843419
from scanner.engine import load_rule
from scanner.mitigation import find_843419_mitigation


RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@dataclass(frozen=True)
class ErrataRule:
    errata_id: str
    name: str
    description: str
    sequence: str
    status: str
    path: Path
    implementation: str = None
    detector: object = None
    mitigation_detector: object = None


DETECTORS = {
    "detect_835769": detect_835769,
    "detect_843419": detect_843419,
}

MITIGATIONS = {
    "find_843419_mitigation": find_843419_mitigation,
}


def load_rules(directory=RULES_DIR):
    """Load YAML metadata and bind each rule to its Python detector."""
    rules = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        data = load_rule(path)
        required = ("id", "name", "description", "sequence", "status")
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError(f"Rule {path} is missing: {', '.join(missing)}")
        implementation_name = data.get("implementation")
        detector = DETECTORS.get(implementation_name) if implementation_name else None
        if implementation_name and detector is None:
            raise ValueError(f"Rule {path} has unknown implementation: {data['implementation']}")
        mitigation_name = data.get("mitigation_implementation")
        mitigation_detector = MITIGATIONS.get(mitigation_name)
        if mitigation_name and mitigation_detector is None:
            raise ValueError(f"Rule {path} has unknown mitigation implementation: {mitigation_name}")
        rule = ErrataRule(
            errata_id=str(data["id"]),
            name=data["name"],
            description=data["description"],
            sequence=str(data["sequence"]),
            status=data["status"],
            path=path,
            implementation=implementation_name,
            detector=detector,
            mitigation_detector=mitigation_detector,
        )
        if rule.errata_id in rules:
            raise ValueError(f"Duplicate errata rule: {rule.errata_id}")
        rules[rule.errata_id] = rule
    return rules


def get_rule(errata_id):
    """Return one configured rule or raise KeyError for an unknown ID."""
    return load_rules()[errata_id]


def rule_detectors():
    return {errata_id: rule.detector for errata_id, rule in load_rules().items()}