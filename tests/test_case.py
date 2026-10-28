import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from analyze_case import analyze_collection, decode_command, utc_time


class CaseTests(unittest.TestCase):
    def make_collection(self, directory, tamper=False, unlabelled=False, uncorrelated=False):
        files = {name: (ROOT / "fixtures/SOC-CASE-001" / name).read_bytes()
                 for name in ("alert.json", "events.jsonl")}
        if unlabelled or uncorrelated:
            alert = json.loads(files["alert.json"])
            if unlabelled:
                alert["synthetic"] = False
            if uncorrelated:
                alert["data"]["win"]["eventdata"]["processGuid"] = "missing-process"
            files["alert.json"] = json.dumps(alert).encode()
        rows = []
        path = Path(directory) / "collection.zip"
        with ZipFile(path, "w") as archive:
            for name, data in files.items():
                stored = f"uploads/auto/fixture/{name}"
                rows.append({"FileName": name, "Size": len(data), "SHA256": hashlib.sha256(data).hexdigest(),
                             "Upload": {"StoredName": "/" + stored}})
                archive.writestr(stored, data if not tamper or name != "alert.json" else data.replace(b"100100", b"100101"))
            archive.writestr("results/Custom.SOC.CaseFiles.json", "\n".join(json.dumps(row) for row in rows))
        return path

    def test_case_and_ground_truth(self):
        truth = json.loads((ROOT / "scenarios/ground-truth.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            result = analyze_collection(self.make_collection(directory))
        self.assertEqual(result["decoded_text"], truth["expected_decoded_text"])
        self.assertEqual([row["record_id"] for row in result["timeline"]], truth["expected_record_order"])
        self.assertEqual(result["timeline"][0]["event_time_utc"], "2026-10-28T04:30:00Z")
        self.assertEqual(len(result["evidence_manifest"]), 2)
        self.assertEqual(result["alert_record_id"], "103")

    def test_tampered_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                analyze_collection(self.make_collection(directory, tamper=True))

    def test_real_or_unlabelled_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "synthetic"):
                analyze_collection(self.make_collection(directory, unlabelled=True))

    def test_uncorrelated_alert_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "correlate"):
                analyze_collection(self.make_collection(directory, uncorrelated=True))

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            utc_time("2026-10-28T04:30:00")

    def test_invalid_base64_is_rejected(self):
        with self.assertRaises(ValueError):
            decode_command("powershell.exe -enc %%%")

    def test_invalid_utf16_is_rejected(self):
        with self.assertRaises(UnicodeDecodeError):
            decode_command("powershell.exe -enc " + base64.b64encode(b"x").decode())

    def test_plain_command_has_no_encoded_argument(self):
        with self.assertRaisesRegex(ValueError, "No supported"):
            decode_command("powershell.exe -Command Get-Date")


if __name__ == "__main__":
    unittest.main(verbosity=2)
