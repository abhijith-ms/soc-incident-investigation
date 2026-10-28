# Tools and validation record

Validated 28 October 2026. Runtime files are stored under `/mnt/Games/SOC`; source remains in this Git repository.

## Official downloads

Velociraptor 0.77.3 Linux AMD64, commit `7d287b0b9`, was downloaded from its [official release](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.3). Compressed asset: `velociraptor-v0.77.3-linux-amd64.gz`; SHA-256: `c2c4eb585f16b622cd57de04995a7a13c076ee455bc2a828fd9243cec2ccfed8`.

CyberChef 11.5.0 was downloaded from its [official release](https://github.com/gchq/CyberChef/releases/tag/v11.5.0). Asset: `CyberChef_8cd426dd4f40f1423912d5fad91b578a86a65112.zip`; SHA-256: `f6478925d3eaa16ec08626a85f5b85eed10d531a5e18700615fed7ecb024cccf`.

Both compressed-asset hashes were compared with GitHub release metadata before unpacking. This is an integrity check against the release metadata, not independent signer verification. No binaries or release archives are committed to the source repository.

## Measured results

- The real Velociraptor CLI completed the custom acquisition with `Error: null` and produced a collection containing exactly the two requested evidence files.
- The analyzer verified both acquired-file hashes, correlated process record `103`, decoded `Write-Output 'SOC-LAB-P2'` and produced four UTC-ordered timeline rows.
- `scripts/run-case.sh` completed a fresh collection and analysis successfully; each run uses a unique output directory.
- All eight Python unit tests passed: the expected case, evidence tampering, non-synthetic inputs, failed alert correlation, missing timezone, invalid Base64, invalid UTF-16 and an unencoded comparison command.
- CyberChef's actual local UI displayed the same decoded text with the saved recipe logic. The check used installed headless Chromium, allowed only localhost HTTP requests, then closed the browser and temporary server. The [screenshot](../examples/SOC-CASE-001/cyberchef.png) captures the synthetic input and output.

The example manifest and timeline were copied from a successful native collection's analysis outputs. They are labelled synthetic and contain fictional host/account details. Raw collection archives remain outside Git because their container metadata can include local machine information.

## Implementation limit and tool issue

This first increment analyzes only the two small labelled JSON exports selected by `Custom.SOC.CaseFiles`. It is not a general EVTX parser, an automated incident classifier or a Windows offline collector. A successful fixture run does not validate a real Windows endpoint or the first project's agent and indexing path.

The optional Velociraptor `--hard_memory_limit` flag caused an upstream nil-map panic in the downloaded 0.77.3 CLI during the initial attempt. The successful collection omitted that flag. The runner sets Go's advisory `GOMEMLIMIT=256MiB` and a 30-second collection timeout; it does not claim a hard memory cap. No permanent server, management port or agent was installed.
