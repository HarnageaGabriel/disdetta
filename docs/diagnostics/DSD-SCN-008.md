# DSD-SCN-008: File larger than the size limit

Error diagnostic: a file larger than 16 MiB was not scanned. It may hold findings, so the scan is incomplete (exit code 3 when the finding policy passes) and the file counts in `summary.filesSkipped`.
