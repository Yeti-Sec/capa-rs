# capa-rs demo — all sample types in one recording

Output demos/all_samples.gif

Set Shell "powershell"
Set FontSize 14
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 30ms

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

Type "# 1/6  .NET assembly"
Enter
Sleep 0.5s
Type "capa-rs -f dotnet samples\dotnet"
Enter
Sleep 8s

Type "# 2/6  ELF x86-64 (static-pie, stripped)"
Enter
Sleep 0.5s
Type "capa-rs samples\elf"
Enter
Sleep 8s

Type "# 3/6  Golang PE32"
Enter
Sleep 0.5s
Type "capa-rs samples\golang"
Enter
Sleep 8s

Type "# 4/6  GraalVM native-image PE64"
Enter
Sleep 0.5s
Type "capa-rs samples\graalvm"
Enter
Sleep 8s

Type "# 5/6  Cobalt Strike beacon"
Enter
Sleep 0.5s
Type "capa-rs samples\shellcode_beacon"
Enter
Sleep 8s

Type "# 6/6  Cobalt Strike beacon (variant 2)"
Enter
Sleep 0.5s
Type "capa-rs samples\shellcode_beacon2"
Enter
Sleep 8s

Type "# All 6 samples analyzed"
Enter
Sleep 2s
