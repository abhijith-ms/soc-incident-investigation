# SOC CASE 001 PowerShell investigation exercise

**Classification:** synthetic authorized lab simulation. No real Windows execution, compromise or Windows endpoint acquisition is claimed.

## Trigger and scope

The supplied synthetic alert references Project 1 rule `100100`, level 7, for an encoded PowerShell process on the fictional host `SOC-WIN-LAB`. It is linked to exported process record `103` by host, event record ID, process GUID and command line. The alert is a fixture, not a captured alert from the first project's live deployment.

The investigation covers two fixture exports: `alert.json` and `events.jsonl`. Velociraptor 0.77.3 acquired those specific files on Linux into a collection archive. It did not collect a Windows endpoint, memory image, registry, network capture or scheduled-task inventory.

## Evidence handling

The original collection remains under `/mnt/Games/SOC/incident-investigation`. Analysis reads members directly from the archive without extracting paths onto the host. The analyzer verifies each evidence file against its collected size and SHA-256 before parsing its contents. The [saved manifest](../examples/SOC-CASE-001/manifest.json) records the two source-file hashes. Original fixture bytes remained unchanged during collection and analysis.

Hashes detect changes relative to recorded metadata. They do not establish that an event is truthful, prove a complete chain of custody or protect against an attacker changing both evidence and its reference hashes. The collection archive's hash is also retained in the local `analysis.json` output.

## Timeline and supported findings

The [timeline](../examples/SOC-CASE-001/timeline.csv) preserves the original timestamp and an explicitly normalized UTC timestamp. Records were deliberately supplied out of order; record `101` uses an India timezone offset to exercise normalization.

| Event time UTC on 28 October 2026 | Evidence reference | Recorded behavior |
| --- | --- | --- |
| 04:30:00 | events.jsonl record 101 | `whoami.exe` process creation |
| 04:30:05 | events.jsonl record 102 | `systeminfo.exe` process creation |
| 04:30:10 | events.jsonl record 103 | PowerShell with an encoded command argument |
| 04:30:20 | events.jsonl record 104 | Unencoded PowerShell text-output comparison |

The synthetic alert timestamp is 04:30:11 UTC. It is kept separate from process event time and actual collection time. The one-second gap is invented fixture data and is not a measured detection latency.

Record `103` contains an argument that decodes from Base64 and UTF-16LE to:

```powershell
Write-Output 'SOC-LAB-P2'
```

This exact text only writes a lab marker to standard output. The analyst script decoded it as data and never executed it. CyberChef 11.5.0 independently displayed the same text using the [saved recipe](../recipes/powershell-decode.json); see the [local CyberChef screenshot](../examples/SOC-CASE-001/cyberchef.png).

The four supplied records name the same test account and parent-process GUID. No parent process-creation record was supplied, so that parent has not been independently reconstructed. A current process list was not collected and cannot be used to establish historical execution here.

## Assessment and disposition

The encoded PowerShell text is benign and matches the separately recorded scenario ground truth. The appropriate disposition for this exercise is an authorized simulation with an expected detection pattern. That conclusion applies to these controlled fixtures, not to arbitrary encoded PowerShell alerts.

There is no evidence in this dataset of malicious payload execution. Network communication, persistence, credential access and exfiltration were not collected, so this exercise cannot rule them out in a real environment. Discovery commands alone do not establish an attacker or malicious intent.

## Response recommendations and detection feedback

No containment or destructive response was performed. For this authorized fixture case, preserve the evidence and close the exercise with its limitations recorded. In a real case, obtain the original endpoint events, verify account authorization and parent process context, scope related activity and escalate according to the evidence before recommending containment.

Keep Project 1's encoded-command detection as a triage signal. Do not globally allowlist encoded PowerShell merely because this example was benign. The proposed next improvement is to enrich triage notes with parent process and user authorization context, then validate that approach against both benign and suspicious comparison cases. This recommendation has not yet been implemented in the first project.

## Remaining validation

Live validation requires running the scenario on an isolated Windows VM, capturing the original Wazuh alert and executing the selected Windows offline collection. Endpoint acquisition and event correlation remain unverified outside the synthetic dataset.
