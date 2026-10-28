"""Verify and analyze the two-file synthetic Velociraptor case; never execute collected commands."""

import argparse
import base64
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from zipfile import ZipFile


def utc_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Event timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def decode_command(command):
    match = re.search(r"(?i)(?:^|\s)-(?:enc|encodedcommand)\s+(\S+)", command)
    if not match:
        raise ValueError("No supported encoded-command argument found")
    return match[1], base64.b64decode(match[1], validate=True).decode("utf-16-le")


def analyze_collection(path):
    # shortcut: accepts two small labelled JSON fixtures only; extend for real EVTX collection formats later.
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("Collection exceeds the exercise's 10 MiB size limit")
    evidence = {}
    manifest = []
    with ZipFile(path) as archive:
        if len(archive.namelist()) != len(set(archive.namelist())):
            raise ValueError("Duplicate archive entries")
        result_name = "results/Custom.SOC.CaseFiles.json"
        if archive.getinfo(result_name).file_size > 1024 * 1024:
            raise ValueError("Collection manifest is too large")
        rows = [json.loads(line) for line in archive.read(result_name).decode().splitlines()]
        if sorted(row["FileName"] for row in rows) != ["alert.json", "events.jsonl"]:
            raise ValueError("Expected exactly alert.json and events.jsonl")
        for row in rows:
            member = row["Upload"]["StoredName"].lstrip("/")
            if not member.startswith("uploads/") or Path(member).name != row["FileName"]:
                raise ValueError("Unexpected evidence member")
            info = archive.getinfo(member)
            if info.file_size > 1024 * 1024 or info.file_size != row["Size"]:
                raise ValueError("Evidence size does not match collection metadata")
            data = archive.read(member)
            digest = hashlib.sha256(data).hexdigest()
            if digest != row["SHA256"]:
                raise ValueError(f"Evidence SHA-256 mismatch: {row['FileName']}")
            evidence[row["FileName"]] = data
            manifest.append({"file": row["FileName"], "bytes": len(data), "sha256": digest})

    alert = json.loads(evidence["alert.json"])
    events = [json.loads(line) for line in evidence["events.jsonl"].decode().splitlines()]
    if alert.get("synthetic") is not True or not events or any(event.get("synthetic") is not True for event in events):
        raise ValueError("This exercise accepts explicitly labelled synthetic evidence only")
    target = alert["data"]["win"]
    matches = [event for event in events if (
        event["win"]["system"]["computer"] == target["system"]["computer"]
        and event["win"]["system"]["eventRecordID"] == target["system"]["eventRecordID"]
        and event["win"]["eventdata"]["processGuid"] == target["eventdata"]["processGuid"]
    )]
    if len(matches) != 1 or matches[0]["win"]["eventdata"]["commandLine"] != target["eventdata"]["commandLine"]:
        raise ValueError("Alert does not correlate to exactly one matching process event")
    encoded, decoded = decode_command(target["eventdata"]["commandLine"])
    timeline = []
    for event in sorted(events, key=lambda item: utc_time(item["win"]["system"]["systemTime"])):
        system, data = event["win"]["system"], event["win"]["eventdata"]
        timeline.append({
            "event_time_utc": utc_time(system["systemTime"]).isoformat().replace("+00:00", "Z"),
            "original_time": system["systemTime"], "host": system["computer"],
            "record_id": system["eventRecordID"], "process_guid": data["processGuid"],
            "user": data["user"], "image": data["image"], "command_line": data["commandLine"],
            "evidence_reference": f"events.jsonl#record-{system['eventRecordID']}",
        })
    return {
        "classification": "synthetic lab exercise", "collection_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "evidence_manifest": manifest, "timeline": timeline,
        "encoded_argument": encoded, "decoded_text": decoded,
        "alert_record_id": target["system"]["eventRecordID"],
        "alert_timestamp": alert["timestamp"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("collection", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze_collection(args.collection)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "analysis.json").write_text(json.dumps(result, indent=2) + "\n")
    (args.output / "manifest.json").write_text(json.dumps(result["evidence_manifest"], indent=2) + "\n")
    (args.output / "decoded.txt").write_text(result["decoded_text"] + "\n")
    (args.output / "cyberchef-input.txt").write_text(result["encoded_argument"] + "\n")
    with (args.output / "timeline.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(result["timeline"][0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(result["timeline"])
    print(f"Verified two evidence files; correlated record {result['alert_record_id']}; wrote {len(result['timeline'])} timeline rows.")
    print(f"Decoded text (data only): {result['decoded_text']}")
    print(f"Analysis saved to {args.output}")


if __name__ == "__main__":
    main()
