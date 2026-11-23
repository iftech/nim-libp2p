# How we would like patches made

## Size and scope of a fix
- As narrow as possible: fix the root cause in the faulty module, no unrelated refactoring or renaming.
- If the same bug exists in sibling code paths (e.g. both muxers, or several protobuf decoders), say so in
  the report rather than fixing all of them in one patch.

## Code style
- Match the surrounding code. Format with `nph` (`make format`); the code must compile with the
  warnings-as-errors and `--styleCheck:error` settings in `config.nims`.
- Keep the existing `{.push raises: [].}` / `async: (raises: [...])` exception tracking; do not widen raised
  exception types or catch `CatchableError` to hide a failure.
- Comments only where the code is not obvious.

## Tests
- Add a regression test to the nearest existing file under `tests/libp2p/` (the layout mirrors `libp2p/`),
  and check it with `make test <path substring>`.

## Branch and commit message
- Against `master`. Subject line in Conventional Commits form, e.g. `fix(yamux): bound the receive window`.
