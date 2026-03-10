# capa-rs demo — ELF binary analysis

Output demos/elf.gif

Set Shell "powershell"
Set FontSize 15
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms

Hide
Type "$env:PATH = 'C:\Users\yeti-sec\Desktop\capa-rs-release\target\release;' + $env:PATH"
Enter
Type "$env:CAPA_RULES = 'C:\Users\yeti-sec\Desktop\capa-rs-release\capa-rules'"
Enter
Type "cd C:\Users\yeti-sec\Desktop\capa-rs-release"
Enter
Sleep 1s
Type "cls"
Enter
Sleep 500ms
Show

Type "# ELF x86-64 (static-pie, stripped)"
Enter
Sleep 1s

Type "capa-rs samples\elf"
Enter
Sleep 8s

Type "capa-rs -v samples\elf"
Enter
Sleep 8s
