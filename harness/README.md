# harness

Execution harness and oracles (Stage 1a). Pattern: Red Canary AtomicTestHarnesses — each implementation returns an oracle outcome `success | fail | blocked`. Events are linked via Sysmon ProcessGuid, never via command-line markers.
