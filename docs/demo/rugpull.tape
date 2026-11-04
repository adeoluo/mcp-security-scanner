# Records docs/demo/rugpull.gif from a real run: `make build demo-server && vhs docs/demo/rugpull.tape` from the repo root.
Output docs/demo/rugpull.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 250
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type `export PS1='$ ' && rm -f bin/demo-runs mcp-lock.json && clear` Enter
Sleep 500ms
Show
Type `./bin/mcpscan pin -- ./bin/mcp-demo-server --variant rugpull --state bin/demo-runs` Enter
Sleep 2.5s
Type `./bin/mcpscan verify -- ./bin/mcp-demo-server --variant rugpull --state bin/demo-runs` Enter
Sleep 6s
Hide
Type `rm -f bin/demo-runs mcp-lock.json` Enter
