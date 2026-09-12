"""Validate abraham Sigma detections against a captured Sysmon event stream.

Implements the detection logic of the registry-linked Sigma rules (ABR-T002,
ABR-T003) verbatim against events exported from the lab VM, and reports
supporting telemetry for ABR-T001/T004 (encrypted channel / polling jitter).

Usage: python lab/validate_capture.py <events.xml>
"""

import sys
import xml.etree.ElementTree as ET
from datetime import datetime

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

T002_INTERACTIVE_PARENTS = [
    "\\explorer.exe", "\\cmd.exe", "\\powershell.exe", "\\pwsh.exe",
    "\\conhost.exe", "\\windowsterminal.exe", "\\wt.exe", "\\wininit.exe",
    "\\winlogon.exe", "\\userinit.exe",
]
T003_EXTENSIONS = [".exe", ".dll", ".ps1", ".bat", ".cmd"]
T003_PATHS = ["\\users\\", "\\windows\\temp\\", "\\programdata\\"]


def load_events(path):
    events = []
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            root = ET.fromstring(line)
            system = root.find(f"{NS}System")
            data = {}
            ed = root.find(f"{NS}EventData")
            if ed is not None:
                for el in ed:
                    data[el.get("Name", "")] = el.text or ""
            events.append({
                "record_id": int(system.find(f"{NS}EventRecordID").text),
                "event_id": int(system.find(f"{NS}EventID").text),
                "time": system.find(f"{NS}TimeCreated").get("SystemTime"),
                **data,
            })
    return events


def rule_t002(ev):
    if ev["event_id"] != 1:
        return False
    if not ev.get("Image", "").lower().endswith("\\cmd.exe"):
        return False
    parent = ev.get("ParentImage", "").lower()
    return not any(parent.endswith(p) for p in T002_INTERACTIVE_PARENTS)


def rule_t003(ev):
    if ev["event_id"] != 11:
        return False
    target = ev.get("TargetFilename", "").lower()
    if not any(target.endswith(ext) for ext in T003_EXTENSIONS):
        return False
    return any(p in target for p in T003_PATHS)


def rule_t007(ev):
    if ev["event_id"] != 1:
        return False
    if not ev.get("Image", "").lower().endswith("\\cmd.exe"):
        return False
    if not ev.get("ParentImage", "").lower().endswith("\\explorer.exe"):
        return False
    return " /C " in ev.get("CommandLine", "")


def fmt_time(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%H:%M:%S.%f")[:-3]


def main():
    events = load_events(sys.argv[1])
    print(f"loaded {len(events)} events "
          f"(record ids {events[0]['record_id']}..{events[-1]['record_id']})\n")

    t002 = [e for e in events if rule_t002(e)]
    t003 = [e for e in events if rule_t003(e)]
    beacons = [e for e in events
               if e["event_id"] == 3 and "abraham-implant" in e.get("Image", "").lower()]
    implant_create = [e for e in events
                      if e["event_id"] == 1 and "abraham-implant" in e.get("Image", "").lower()]

    print(f"== ABR-T002 (sigma 3f9a6c1e-8b2d-4e7f-9c4a-1d6e5b8f2a01): "
          f"{len(t002)} matching events")
    for e in t002:
        print(f"  rec={e['record_id']} t={fmt_time(e['time'])} "
              f"image={e.get('Image')} parent={e.get('ParentImage')} "
              f"cmd={e.get('CommandLine')}")

    print(f"\n== ABR-T003 (sigma 8c2f9d3a-1b4e-4f6a-9c7d-2e8b5a3f1c02): "
          f"{len(t003)} matching events")
    for e in t003:
        print(f"  rec={e['record_id']} t={fmt_time(e['time'])} "
              f"target={e.get('TargetFilename')} image={e.get('Image')}")

    print(f"\n== ABR-T001/T004 support: implant process creations={len(implant_create)}")
    for e in implant_create:
        print(f"  rec={e['record_id']} t={fmt_time(e['time'])} "
              f"image={e.get('Image')} parent={e.get('ParentImage')} user={e.get('User')}")
    print(f"== ABR-T004 support: network events from implant={len(beacons)}")
    times = []
    for e in beacons[:6]:
        print(f"  rec={e['record_id']} t={fmt_time(e['time'])} "
              f"dst={e.get('DestinationIp')}:{e.get('DestinationPort')} "
              f"src={e.get('SourceIp')}:{e.get('SourcePort')}")
        times.append(datetime.fromisoformat(e["time"].replace("Z", "+00:00")))
    if len(times) > 1:
        deltas = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        print(f"  first poll intervals (s): {[round(d, 2) for d in deltas]}")

    verdict_t002 = "MATCH" if t002 else "NO MATCH"
    verdict_t003 = "MATCH" if t003 else "NO MATCH"
    t007 = [e for e in events if rule_t007(e)]
    verdict_t007 = "MATCH" if t007 else "NO MATCH (expected on 25H2: cross-process PPID rejected)"
    print(f"\n== ABR-T007 (sigma 7a4e6c2b-1d93-4f58-a6e0-9b2c7d5f4a03): "
          f"{len(t007)} matching events")
    for e in t007:
        print(f"  rec={e['record_id']} t={fmt_time(e['time'])} "
              f"image={e.get('Image')} parent={e.get('ParentImage')} "
              f"cmd={e.get('CommandLine')}")
    print(f"\nverdict: ABR-T002={verdict_t002} ABR-T003={verdict_t003} ABR-T007={verdict_t007}")
    return 0 if (t002 and t003) else 1


if __name__ == "__main__":
    sys.exit(main())
