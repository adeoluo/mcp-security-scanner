# Records docs/demo/probe.gif from a real run: `make build demo-server && vhs docs/demo/probe.tape` from the repo root.
Output docs/demo/probe.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 400
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type `export PS1='$ ' && clear` Enter
Sleep 500ms
Show
Type `./bin/mcpscan probe --min-severity high -- ./bin/mcp-demo-server --variant poisoned` Enter
Sleep 7s
