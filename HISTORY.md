# Findings history

Written by bork collect, bork issues and bork triage on the host; append only.

- `findings/ab/<fingerprint>.jsonl`: one file per finding, one line per event: sighting, anchor, filed, decision, fixed, fix, fix_request, link. Status is derived by folding the lines, never stored.
- `runs/<task-id>.json`: one audit run: the input manifest and its hash, base, proof and gate commits, the spec by blob id, environment and turns.
- `reports/<task-id>.md`: the human report.
- `specs/<name>.md`: a spec not kept in this repository, as staged for a run; `<name>.source.json` is its provenance.
- `decisions/`: long rationale behind a decision line.

Fingerprint version 1: sha256 over domain, class and the located lines' text at the scanned commit, or the domain's subject.
