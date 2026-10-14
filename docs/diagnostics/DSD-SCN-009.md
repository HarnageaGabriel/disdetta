# DSD-SCN-009: Helm release payload over a cap or not decodable

Error diagnostic: a Helm release Secret payload could not be decoded, or it
exceeded a bounded-decoding cap (spec v0.2 section 4). The compressed payload is
capped at 4 MiB, the decompressed payload at 32 MiB, and the expansion ratio at
100:1; the payload must be base64 (StdEncoding) of gzip-compressed JSON, or a
legacy plain JSON payload. The release is not scanned, so the report is
incomplete (`summary.complete` is false, exit code 3 when the finding policy
passes). No decoded value is ever printed: only the reference and the location.
