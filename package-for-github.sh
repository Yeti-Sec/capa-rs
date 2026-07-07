#!/usr/bin/env bash
# =============================================================================
# package-for-github.sh
#
# Prepares capa-rs for public GitHub distribution.
# Creates a clean release directory, stripping build artifacts, .git metadata,
# vendored crates that have been moved to crates.io/git, and gitignored files.
#
# Usage:
#   bash package-for-github.sh [output_dir]
#
# Default output: ../capa-rs-github/
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"
OUTPUT_DIR="${1:-$(dirname "$SOURCE_DIR")/capa-rs-github}"

echo "=== capa-rs GitHub Packaging Script ==="
echo "Source:    $SOURCE_DIR"
echo "Output:    $OUTPUT_DIR"
echo ""

# -------------------------------------------------------------------------
# 1. Create clean output directory
# -------------------------------------------------------------------------
if [ -d "$OUTPUT_DIR" ]; then
    echo "[!] Output directory exists. Removing: $OUTPUT_DIR"
    rm -rf "$OUTPUT_DIR"
fi
mkdir -p "$OUTPUT_DIR"

# -------------------------------------------------------------------------
# 2. Copy workspace crates
# -------------------------------------------------------------------------
echo "[*] Copying workspace crates..."

WORKSPACE_CRATES=(
    capa-core
    capa-backend
    capa-cli
)

mkdir -p "$OUTPUT_DIR/crates"
for crate in "${WORKSPACE_CRATES[@]}"; do
    if [ -d "$SOURCE_DIR/crates/$crate" ]; then
        echo "    - crates/$crate/"
        cp -r "$SOURCE_DIR/crates/$crate" "$OUTPUT_DIR/crates/"
    fi
done

# Vendored crates still in the workspace (check Cargo.toml members)
VENDORED_CRATES=(
    dotscope
    idalib
    idalib-sys
    idalib-build
    idalib-macros
)

for crate in "${VENDORED_CRATES[@]}"; do
    if [ -d "$SOURCE_DIR/crates/$crate" ] && grep -q "\"crates/$crate\"" "$SOURCE_DIR/Cargo.toml" 2>/dev/null; then
        echo "    - crates/$crate/ (vendored)"
        cp -r "$SOURCE_DIR/crates/$crate" "$OUTPUT_DIR/crates/"
    else
        echo "    - crates/$crate/ — not in workspace members, skipping"
    fi
done

# -------------------------------------------------------------------------
# 3. Copy project source and configuration
# -------------------------------------------------------------------------
echo "[*] Copying project files..."

# Directories
for dir in capa-rules enhanced-dotnet-rules sigs demos docs .github; do
    if [ -d "$SOURCE_DIR/$dir" ]; then
        echo "    - $dir/"
        cp -r "$SOURCE_DIR/$dir" "$OUTPUT_DIR/"
    fi
done

# Top-level files
for f in Cargo.toml Cargo.lock justfile rust-toolchain.toml \
         README.md LICENSE CHANGELOG.md CONTRIBUTING.md SECURITY.md \
         ARCHITECTURE.md BENCHMARKS.md \
         demo.gif demo.tape \
         .gitignore package-for-github.sh; do
    if [ -f "$SOURCE_DIR/$f" ]; then
        echo "    - $f"
        cp "$SOURCE_DIR/$f" "$OUTPUT_DIR/"
    fi
done

# -------------------------------------------------------------------------
# 4. Clean up build artifacts and metadata
# -------------------------------------------------------------------------
echo "[*] Cleaning build artifacts..."

# Remove all target/ directories (cargo build output)
find "$OUTPUT_DIR" -type d -name target -exec rm -rf {} + 2>/dev/null || true

# Remove .git files/directories from vendored crates
find "$OUTPUT_DIR/crates" -name ".git" -exec rm -rf {} + 2>/dev/null || true

# Remove IDA SDK docs if present (large, not needed for building)
if [ -d "$OUTPUT_DIR/crates/idalib-sys/sdk/docs" ]; then
    echo "    - Removing idalib-sys/sdk/docs/ (saves ~50MB)"
    rm -rf "$OUTPUT_DIR/crates/idalib-sys/sdk/docs"
fi

# Remove IDA SDK extras if present
for sdk_extra in plugins modules dbg ldr bin; do
    if [ -d "$OUTPUT_DIR/crates/idalib-sys/sdk/src/$sdk_extra" ]; then
        echo "    - Removing idalib-sys/sdk/src/$sdk_extra/"
        rm -rf "$OUTPUT_DIR/crates/idalib-sys/sdk/src/$sdk_extra"
    fi
done

# Remove benchmark/samples directories (gitignored)
rm -rf "$OUTPUT_DIR/benchmark" "$OUTPUT_DIR/samples" 2>/dev/null || true

# Remove features.json if present
rm -f "$OUTPUT_DIR/features.json" 2>/dev/null || true

# -------------------------------------------------------------------------
# 5. Print summary
# -------------------------------------------------------------------------
echo ""
echo "=== Packaging Complete ==="
echo ""
echo "Output directory: $OUTPUT_DIR"
echo ""
echo "Contents:"
echo "  crates/              Workspace crates"
echo "    capa-core/           Rule engine + matching logic"
echo "    capa-backend/        Binary analysis backends (iced-x86, dotscope, IDA)"
echo "    capa-cli/            CLI interface"
echo "  capa-rules/          Bundled CAPA detection rules (1000+)"
echo "  enhanced-dotnet-rules/ Additional .NET-specific rules"
echo "  sigs/                FLIRT signature files"
echo "  demos/               Terminal recordings"
echo "  docs/                Rule-writing guides"
echo "  .github/             CI workflows + dependabot"
echo ""
echo "To build:"
echo "  cd $OUTPUT_DIR && cargo build --release"
echo ""
echo "To build with .NET support:"
echo "  cd $OUTPUT_DIR && cargo build --release --features dotnet"
echo ""
echo "To build with IDA backend:"
echo "  cd $OUTPUT_DIR && cargo build --release --features ida-backend"
