# Records docs/demo/scan.gif from a real run: `make build && vhs docs/demo/scan.tape` from the repo root.
Output docs/demo/scan.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 380
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type `export PS1='$ ' && clear` Enter
Sleep 500ms
Show
Type `./bin/mcpscan scan testdata/vulnerable-server` Enter
Sleep 6s
