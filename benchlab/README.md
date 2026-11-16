# capa-rs adapter

xBenchLab adapter for `capa-rs`, a Rust reimplementation of Mandiant's `capa` capability detection tool.

## Mode

- `default`: Runs `capa-rs --backend {backend} -r /opt/{rules} --json-document <input>` (`ResultDocument` schema) and normalizes matched rules (`rule_match`), non-library capabilities (`capability`), and MITRE ATT&CK techniques (`attack_technique`) identically to Python `capa`.

## Options

- `backend`: `ida` (default, IDA Pro 9.5 via `idalib`, requires `ida`) or `goblin` (pure-Rust `goblin` + `dotscope`).
- `rules`: `capa-rules` (default) or `enhanced-dotnet-rules`.
