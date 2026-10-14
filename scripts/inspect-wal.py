import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil


def event_checksum(event):
    keys = ("id", "uid", "schema_version", "timestamp", "source", "level", "message", "fields")
    canonical = {key: event[key] for key in keys if key != "fields"}
    canonical["fields"] = dict(sorted(event.get("fields", {}).items()))
    encoded = json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    value = 0xCBF29CE484222325
    for byte in encoded:
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


def valid(record):
    try:
        return record["version"] == 1 and record["checksum"] == event_checksum(record["event"])
    except (KeyError, TypeError, ValueError, UnicodeError):
        return False


def inspect(path):
    before = path.stat()
    digest = hashlib.sha256()
    decoder = json.JSONDecoder()
    report = {"bytes": before.st_size, "valid_records": 0, "invalid_records": 0, "salvageable_records": 0, "invalid_samples": []}
    offset = 0
    with path.open("rb") as stream:
        for number, line in enumerate(stream, 1):
            digest.update(line)
            if not line.strip():
                offset += len(line)
                continue
            try:
                record = json.loads(line)
                reason = "checksum_or_version" if not valid(record) else None
            except (ValueError, UnicodeError):
                reason = "invalid_json"
            if reason is None:
                report["valid_records"] += 1
            else:
                report["invalid_records"] += 1
                sample = {"line": number, "offset": offset, "bytes": len(line), "reason": reason, "terminated": line.endswith(b"\n"), "candidates": []}
                position = 0
                while reason == "invalid_json":
                    position = line.find(b'{"version":', position)
                    if position < 0:
                        break
                    try:
                        text = line[position:].decode("utf-8")
                        candidate, consumed = decoder.raw_decode(text)
                        if valid(candidate):
                            length = len(text[:consumed].encode("utf-8"))
                            report["salvageable_records"] += 1
                            if len(sample["candidates"]) < 8:
                                sample["candidates"].append({"offset": offset + position, "bytes": length, "uid": candidate["event"]["uid"]})
                            position += length
                            continue
                    except (ValueError, UnicodeError, TypeError):
                        pass
                    position += 1
                if len(report["invalid_samples"]) < 8:
                    report["invalid_samples"].append(sample)
            offset += len(line)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError("WAL changed during inspection; retry with the collector stopped")
    report["sha256"] = digest.hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("wal", type=Path)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--working-copy", type=Path)
    arguments = parser.parse_args()
    report = inspect(arguments.wal)
    if arguments.working_copy:
        if not arguments.working_copy.parent.is_dir():
            raise RuntimeError("Working copy parent must already exist")
        os.umask(0o077)
        arguments.working_copy.mkdir(mode=0o700)
        destination = arguments.working_copy / "active.wal"
        with arguments.wal.open("rb") as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
        if inspect(destination)["sha256"] != report["sha256"]:
            raise RuntimeError("Working copy differs from the inspected WAL")
    if arguments.snapshot:
        if not arguments.snapshot.parent.is_dir():
            raise RuntimeError("Snapshot parent must already exist")
        os.umask(0o077)
        arguments.snapshot.mkdir(mode=0o700)
        destination = arguments.snapshot / "original.wal"
        with arguments.wal.open("rb") as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
        snapshot = inspect(destination)
        if snapshot["sha256"] != report["sha256"]:
            raise RuntimeError("Snapshot differs from the inspected WAL")
        for name in ("catalog.json", "checkpoints.json"):
            source = arguments.wal.parent / name
            if source.is_file():
                shutil.copyfile(source, arguments.snapshot / name)
        (arguments.snapshot / "inspection.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
