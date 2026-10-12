# ADR 0003: Severity model

Status: accepted

Severity is ordered `DSD-SEV-1` (`allowInsecureImages`), `DSD-SEV-2`
(`bitnamilegacy`), then `DSD-SEV-3` (current Bitnami images and chart sources).
Stateful repositories sort before severity so migration risk remains visible.
Within those keys, output is ordered by path and line.
