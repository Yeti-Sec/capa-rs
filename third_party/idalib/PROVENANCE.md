# Vendored `idalib` (IDA 9.5 / v0.11.1)

REUSE-DECISION: idalib 9.5 bindings | reused | source=floss-rs:third_party/idalib + Yeti-Sec/idalib@22b61bb,0c3cc8e | why=Yeti-Sec/idalib@0c3cc8e targets IDA 9.2 and fails clang-22 binding generation (gdl_graph_t C2259); reused floss-rs vendored upstream v0.11.1+9.5.261026 (MIT) with capa-rs import enumeration and instruction helpers ported forward.

## Source

- Upstream: <https://github.com/idalib-rs/idalib>, tag `v0.11.1+9.5.261026`,
  commit `26989c87a326c93cd0d1d38673dd68302d7afa4c` (IDA 9.5 support), adapted
  from `floss-rs/third_party/idalib`.
- Vendored crates: `idalib`, `idalib-sys`, `idalib-build`, `idalib-macros`.
- License: `MIT OR Apache-2.0`; redistributed under the MIT option (`LICENSE-MIT`).

## Local patches applied on top of v0.11.1

1. **`IDASDK_ROOT` SDK resolution & version gate (`EXPECTED_IDA_SDK_VERSION = 950`)** in `idalib-sys/build.rs` (no submodule or network fetch required; proprietary Hex-Rays SDK is supplied at build time via `IDASDK_ROOT`).
2. **`block!("_IO_FILE")` / `__sFILE` / `_iobuf`** in `idalib-sys/src/lib.rs` (`Yeti-Sec/idalib@c47977d`).
3. **Import enumeration & instruction helpers** (`Yeti-Sec/idalib@22b61bb`):
   - `idalib::imports::enum_all_imports()` (`nalt_extras.h`, `idalib/src/imports.rs`) for module-qualified import extraction in `capa-backend/src/ida_loader.rs`.
   - `Insn::segpref()`, `Insn::disasm_line()`, `Insn::print_operand()`, and `IDB::{mnemonic_at, disasm_line_at, print_operand_at}` (`ua_extras.h`, `idalib/src/insn.rs`, `idalib/src/idb.rs`).
4. **Headless container open fix** (`Yeti-Sec/idalib@0c3cc8e`): skip redundant `is_license_valid()` inside `open_database_with` / `open_database_quiet` since `init_library()` already validates the license.
5. **FLIRT signature application** (capa-rs local, wraps `funcs.hpp` `plan_to_apply_idasgn`, `apply_idasgn_to`, `get_idasgn_qty`, `calc_idasgn_state`, `get_idasgn_desc`):
   - `idalib-sys/src/flirt_extras.h` (new C++ helpers), declarations and `idalib_sys::ida::{plan_to_apply_idasgn, apply_idasgn_to, get_idasgn_qty, calc_idasgn_state, get_idasgn_matches}` in `idalib-sys/src/lib.rs`.
   - `IDB::{plan_to_apply_idasgn, idasgn_qty, idasgn_state, idasgn_matches}` in `idalib/src/idb.rs`.
   - Used by `capa-backend/src/ida_flirt.rs`; opt-in only (`--signatures` / `CAPA_SIGS_DIR`). IDA takes a short file name resolved in `$IDADIR/sig/pc` / `$IDAUSR/sig/pc`.
