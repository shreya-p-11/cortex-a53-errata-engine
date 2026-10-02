from dataclasses import dataclass
from pathlib import Path

import yaml

from scanner.detector import detect_835769, detect_843419


RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@dataclass(frozen=True)
class ErrataRule:
    errata_id: str
    name: str
    implementation: str
    description: str
    sequence: str
    status: str
    detector: object


DETECTORS = {
    "detect_835769": detect_835769,
    "detect_843419": detect_843419,
}


def load_rules(directory=RULES_DIR):
    """Load YAML metadata and bind each rule to its Python detector."""
    rules = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream) or {}
        required = ("id", "name", "implementation", "description", "sequence", "status")
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError(f"Rule {path} is missing: {', '.join(missing)}")
        detector = DETECTORS.get(data["implementation"])
        if detector is None:
            raise ValueError(f"Rule {path} has unknown implementation: {data['implementation']}")
        rule = ErrataRule(
            errata_id=str(data["id"]),
            name=data["name"],
            implementation=data["implementation"],
            description=data["description"],
            sequence=str(data["sequence"]),
            status=data["status"],
            detector=detector,
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