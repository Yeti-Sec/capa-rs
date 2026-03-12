# capa-rs demo — static capability detection for PE/ELF binaries
# Usage: vhs demo.tape
# Requires: capa-rs built (target/release/capa-rs.exe) and a sample binary

Output demo.gif

Require capa-rs

Set Shell "pwsh"
Set FontSize 15
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms
Set CursorBlink false

# ── Title ──
Type "# capa-rs — fast capability detection for PE/ELF binaries"
Enter
Sleep 1s

# ── Show help ──
Type "capa-rs --help"
Enter
Sleep 3s

# ── Analyze a binary ──
Type "capa-rs sample.exe"
Enter
Sleep 5s

# ── Verbose output with match locations ──
Type "capa-rs -v sample.exe"
Enter
Sleep 5s

# ── JSON output for automation ──
Type "capa-rs -j sample.exe | head -40"
Enter
Sleep 4s

# ── Namespace filtering ──
Type "capa-rs -n anti-analysis sample.exe"
Enter
Sleep 4s

# ── Done ──
Type "# ~10x faster than Python capa"
Enter
Sleep 2s
