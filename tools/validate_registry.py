import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "registry" / "techniques.yaml"

ID_PATTERN = re.compile(r"^ABR-T\d{3}$")
VALID_STATUSES = {"planned", "experimental", "stable", "deprecated"}
VALID_DETECTION_TYPES = {"sigma", "yara", "etw", "kql", "guidance"}
REQUIRED_FIELDS = (
    "id",
    "name",
    "description",
    "mitre_attack",
    "component",
    "phase",
    "status",
    "detections",
)


def main():
    errors = []
    with REGISTRY_PATH.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if data.get("schema_version") != 1:
        print("error: unsupported schema_version")
        return 1

    techniques = data.get("techniques") or []
    if not techniques:
        print("error: no techniques defined")
        return 1

    seen_ids = set()
    for technique in techniques:
        technique_id = technique.get("id", "<missing>")
        for field in REQUIRED_FIELDS:
            if field not in technique:
                errors.append(f"{technique_id}: missing field '{field}'")
        if not ID_PATTERN.match(str(technique.get("id", ""))):
            errors.append(f"{technique_id}: id must match ABR-T###")
        if technique_id in seen_ids:
            errors.append(f"{technique_id}: duplicate id")
        seen_ids.add(technique_id)
        if technique.get("status") not in VALID_STATUSES:
            errors.append(
                f"{technique_id}: status must be one of "
                + ", ".join(sorted(VALID_STATUSES))
            )
        phase = technique.get("phase")
        if not isinstance(phase, int) or not 1 <= phase <= 5:
            errors.append(f"{technique_id}: phase must be an integer 1-5")
        if not isinstance(technique.get("mitre_attack"), list) or not technique.get(
            "mitre_attack"
        ):
            errors.append(f"{technique_id}: mitre_attack must be a non-empty list")
        detections = technique.get("detections") or []
        if not detections:
            errors.append(f"{technique_id}: at least one detection is required")
        for detection in detections:
            if detection.get("type") not in VALID_DETECTION_TYPES:
                errors.append(
                    f"{technique_id}: unknown detection type "
                    f"'{detection.get('type')}'"
                )
            path = detection.get("path")
            if not path or not (ROOT / path).is_file():
                errors.append(f"{technique_id}: detection path missing on disk: {path}")

    if errors:
        for error in errors:
            print(f"error: {error}")
        print(f"{len(errors)} error(s)")
        return 1

    print(f"registry OK: {len(techniques)} techniques validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
