# PowerShell Incident Investigation and Endpoint Forensics

A scoped evidence-collection and analysis workflow for an encoded-PowerShell alert, using Velociraptor, CyberChef and Python.

**Status:** acquisition and analysis are validated using two labelled synthetic Windows event exports collected on Linux. A real Windows endpoint collection and live Wazuh alert remain pending.

## Investigation workflow

```text
Synthetic PowerShell alert and process events
    -> Scoped Velociraptor file acquisition
    -> File size and SHA-256 verification
    -> Alert-to-process correlation
    -> Base64 and UTF-16LE decoding
    -> UTC timeline and case report
```

The collector selects only `alert.json` and `events.jsonl`. The analyzer verifies the acquired files, correlates the alert by host, record ID, process GUID and command line, and decodes the command as data without executing it. The scenario ground truth is stored separately and is not acquired by the collector.

## Run collection and analysis

Requirements: Python 3 and the verified Velociraptor 0.77.3 Linux AMD64 binary at `/mnt/Games/SOC/tools/velociraptor-v0.77.3-linux-amd64`. The runner uses the existing runtime directory `/mnt/Games/SOC/incident-investigation`.

```bash
bash scripts/run-case.sh
python3 -m unittest discover -s tests -v
```

Each collection creates a new runtime directory containing `collection.zip` and an `analysis` directory. Analysis outputs include a verified file manifest, a four-event UTC timeline, decoded text, CyberChef input and the collection archive's hash. Existing collections are not overwritten.

The [CyberChef recipe](recipes/powershell-decode.json) applies From Base64 followed by Decode text using UTF-16LE. The local CyberChef UI independently produced the same harmless output as the analyzer: `Write-Output 'SOC-LAB-P2'`.

## Validation and results

All eight analysis tests passed, covering the expected case, evidence tampering, non-synthetic input, failed alert correlation, missing timezone, invalid Base64, invalid UTF-16 and an unencoded comparison command. See the [tools and validation record](docs/tools-and-validation.md) for release hashes, measured results and implementation limits.

- [Case report](reports/SOC-CASE-001.md)
- [UTC timeline](examples/SOC-CASE-001/timeline.csv)
- [Evidence manifest](examples/SOC-CASE-001/manifest.json)
- [CyberChef output](examples/SOC-CASE-001/cyberchef.png)

## Repository contents

| Path | Purpose |
| --- | --- |
| [artifacts](artifacts/) | Scoped Velociraptor collection definition |
| [fixtures/SOC-CASE-001](fixtures/SOC-CASE-001/) | Synthetic alert and process-event exports |
| [scripts](scripts/) | Collection runner and evidence analyzer |
| [tests](tests/) | Analysis and input-validation tests |
| [recipes](recipes/) | Reproducible CyberChef decoding recipe |
| [reports](reports/) | Investigation findings and disposition |
| [windows/generate-scenario.ps1](windows/generate-scenario.ps1) | Prepared Windows scenario generator; live execution pending |

The current analyzer accepts only the two small labelled synthetic JSON exports. It does not parse EVTX files or collect Windows memory, registry or network evidence. The case report distinguishes fixture observations from recommended response actions; no containment action was performed.

## References

- [Velociraptor](https://github.com/Velocidex/velociraptor)
- [CyberChef](https://github.com/gchq/CyberChef)
