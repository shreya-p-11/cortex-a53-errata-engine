from dataclasses import dataclass
from pathlib import Path
import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

@dataclass(frozen=True)
class ErrataRule:
    errata_id: str
    name: str
    description: str
    status: str
    path: Path
    structural: dict
    mitigation_structural: dict = None

def load_rules(directory=RULES_DIR):
    """Load YAML metadata and return a dictionary of ErrataRule objects."""
    rules = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream) or {}
            
        required = ("id", "name", "description", "status", "structural")
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError(f"Rule {path} is missing: {', '.join(missing)}")

        rule = ErrataRule(
            errata_id=str(data["id"]),
            name=data["name"],
            description=data["description"],
            status=data["status"],
            path=path,
            structural=data["structural"],
            mitigation_structural=data.get("mitigation_structural")
        )
        if rule.errata_id in rules:
            raise ValueError(f"Duplicate errata rule: {rule.errata_id}")
        rules[rule.errata_id] = rule
    return rules