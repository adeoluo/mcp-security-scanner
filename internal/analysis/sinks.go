package analysis

import (
	"regexp"
	"strings"

	"github.com/adeoluo/mcp-security-scanner/internal/lexer"
)

// Taint bits: which sink classes a value is still dangerous for.
const (
	tCmd  uint8 = 1 << iota // shell and code execution
	tPath                   // file system paths
	tURL                    // host part of outbound URLs
	tAll  = tCmd | tPath | tURL
)

type sinkKind uint8

const (
	sinkNone sinkKind = iota
	sinkShell
	sinkCode
	sinkPath
	sinkURL
	sinkSpawn    // spawn/execFile/subprocess.*: shell only with shell option or "sh -c"
	sinkPathRecv // Python pathlib method on a tainted receiver
)

type sinkSpec struct {
	kind sinkKind
	arg  int // argument index to check; -1 means any argument
}

var jsSinks = map[string]sinkSpec{
	"child_process.exec": {sinkShell, 0}, "child_process.execSync": {sinkShell, 0},
	"child_process.spawn": {sinkSpawn, -1}, "child_process.spawnSync": {sinkSpawn, -1},
	"child_process.execFile": {sinkSpawn, -1}, "child_process.execFileSync": {sinkSpawn, -1},
	"shelljs.exec": {sinkShell, 0}, "execa.execaCommand": {sinkSpawn, -1}, "execa.execa": {sinkSpawn, -1},
	"eval": {sinkCode, 0}, "Function": {sinkCode, -1}, "vm.runInNewContext": {sinkCode, 0},
	"vm.runInThisContext": {sinkCode, 0}, "vm.runInContext": {sinkCode, 0}, "vm.Script": {sinkCode, 0},
	"vm.compileFunction": {sinkCode, 0},
	"fetch":              {sinkURL, 0}, "undici.fetch": {sinkURL, 0}, "undici.request": {sinkURL, 0},
	"axios": {sinkURL, -1}, "axios.get": {sinkURL, 0}, "axios.post": {sinkURL, 0}, "axios.put": {sinkURL, 0},
	"axios.patch": {sinkURL, 0}, "axios.delete": {sinkURL, 0}, "axios.head": {sinkURL, 0},
	"axios.request": {sinkURL, -1}, "axios.options": {sinkURL, 0},
	"got": {sinkURL, 0}, "got.get": {sinkURL, 0}, "got.post": {sinkURL, 0}, "ky": {sinkURL, 0}, "ky.get": {sinkURL, 0},
	"http.get": {sinkURL, 0}, "http.request": {sinkURL, 0}, "https.get": {sinkURL, 0}, "https.request": {sinkURL, 0},
	"request": {sinkURL, 0}, "needle": {sinkURL, 1}, "superagent.get": {sinkURL, 0}, "superagent.post": {sinkURL, 0},
}

var jsFsOps = map[string]int{
	"readFile": 0, "readFileSync": 0, "writeFile": 0, "writeFileSync": 0, "appendFile": 0, "appendFileSync": 0,
	"createReadStream": 0, "createWriteStream": 0, "unlink": 0, "unlinkSync": 0, "rm": 0, "rmSync": 0,
	"rmdir": 0, "rmdirSync": 0, "mkdir": 0, "mkdirSync": 0, "readdir": 0, "readdirSync": 0, "opendir": 0,
	"copyFile": -1, "copyFileSync": -1, "cp": -1, "cpSync": -1, "rename": -1, "renameSync": -1, "open": 0,
	"openSync": 0, "symlink": -1, "truncate": 0, "readJson": 0, "readJSON": 0, "writeJson": 0, "outputFile": 0,
	"outputJson": 0, "remove": 0, "removeSync": 0, "copy": -1, "move": -1, "emptyDir": 0, "readJsonSync": 0,
}

var pySinks = map[string]sinkSpec{
	"os.system": {sinkShell, 0}, "os.popen": {sinkShell, 0}, "subprocess.getoutput": {sinkShell, 0},
	"subprocess.getstatusoutput": {sinkShell, 0}, "commands.getoutput": {sinkShell, 0},
	"asyncio.create_subprocess_shell": {sinkShell, 0},
	"subprocess.run":                  {sinkSpawn, 0}, "subprocess.call": {sinkSpawn, 0}, "subprocess.check_call": {sinkSpawn, 0},
	"subprocess.check_output": {sinkSpawn, 0}, "subprocess.Popen": {sinkSpawn, 0},
	"asyncio.create_subprocess_exec": {sinkSpawn, -1},
	"eval":                           {sinkCode, 0}, "exec": {sinkCode, 0},
	"open": {sinkPath, 0}, "io.open": {sinkPath, 0}, "aiofiles.open": {sinkPath, 0}, "codecs.open": {sinkPath, 0},
	"os.remove": {sinkPath, 0}, "os.unlink": {sinkPath, 0}, "os.rmdir": {sinkPath, 0}, "os.removedirs": {sinkPath, 0},
	"os.listdir": {sinkPath, 0}, "os.scandir": {sinkPath, 0}, "os.makedirs": {sinkPath, 0}, "os.mkdir": {sinkPath, 0},
	"os.rename": {sinkPath, -1}, "os.replace": {sinkPath, -1}, "os.walk": {sinkPath, 0},
	"shutil.rmtree": {sinkPath, 0}, "shutil.copy": {sinkPath, -1}, "shutil.copy2": {sinkPath, -1},
	"shutil.copyfile": {sinkPath, -1}, "shutil.copytree": {sinkPath, -1}, "shutil.move": {sinkPath, -1},
	"flask.send_file": {sinkPath, 0}, "starlette.responses.FileResponse": {sinkPath, 0}, "fastapi.responses.FileResponse": {sinkPath, 0},
	"requests.get": {sinkURL, 0}, "requests.post": {sinkURL, 0}, "requests.put": {sinkURL, 0},
	"requests.patch": {sinkURL, 0}, "requests.delete": {sinkURL, 0}, "requests.head": {sinkURL, 0},
	"requests.request": {sinkURL, 1}, "httpx.get": {sinkURL, 0}, "httpx.post": {sinkURL, 0}, "httpx.put": {sinkURL, 0},
	"httpx.patch": {sinkURL, 0}, "httpx.delete": {sinkURL, 0}, "httpx.request": {sinkURL, 1}, "httpx.stream": {sinkURL, 1},
	"urllib.request.urlopen": {sinkURL, 0}, "urllib.request.Request": {sinkURL, 0}, "urllib.request.urlretrieve": {sinkURL, 0},
	"urllib3.request": {sinkURL, 1}, "aiohttp.request": {sinkURL, 1},
}

var pyPathMethods = map[string]bool{
	"read_text": true, "read_bytes": true, "write_text": true, "write_bytes": true, "unlink": true,
	"rmdir": true, "iterdir": true, "rename": true, "touch": true, "mkdir": true, "open": true, "rglob": true, "glob": true,
}

var httpMethods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "request": true, "stream": true, "fetch": true}

var reHTTPReceiver = regexp.MustCompile(`(?i)(client|session|http|requests|httpx|axios)$`)

var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "/bin/sh": true, "/bin/bash": true, "/bin/zsh": true, "cmd": true,
	"cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true, "/usr/bin/env": false,
}

// lookupSink returns the sink for a resolved callee name.
func (f *File) lookupSink(canon string, segs []string) (sinkSpec, bool) {
	if f.Lang == lexer.Python {
		if s, ok := pySinks[canon]; ok {
			// a local function named open/exec/eval shadows the builtin
			if len(segs) == 1 && f.aliases[segs[0]] == "" && f.definesFunc(segs[0]) {
				return sinkSpec{}, false
			}
			return s, true
		}
		if len(segs) >= 2 {
			last := segs[len(segs)-1]
			if httpMethods[last] && reHTTPReceiver.MatchString(segs[len(segs)-2]) {
				return sinkSpec{sinkURL, 0}, true
			}
			if strings.HasPrefix(canon, "httpx.") || strings.HasPrefix(canon, "aiohttp.") {
				if httpMethods[last] {
					return sinkSpec{sinkURL, 0}, true
				}
			}
		}
		return sinkSpec{}, false
	}
	if s, ok := jsSinks[canon]; ok {
		if len(segs) == 1 && f.aliases[segs[0]] == "" && canon != "fetch" && canon != "eval" && canon != "Function" {
			return sinkSpec{}, false // e.g. a local "request" helper, not the module
		}
		if len(segs) == 1 && f.definesFunc(segs[0]) {
			return sinkSpec{}, false
		}
		return s, true
	}
	if strings.HasPrefix(canon, "fs.") {
		op := canon[3:]
		if idx, ok := jsFsOps[op]; ok {
			return sinkSpec{sinkPath, idx}, true
		}
	}
	if len(segs) == 2 && (segs[1] == "sendFile" || segs[1] == "download") && (segs[0] == "res" || segs[0] == "response" || segs[0] == "reply") {
		return sinkSpec{sinkPath, 0}, true
	}
	if len(segs) >= 2 {
		last := segs[len(segs)-1]
		if httpMethods[last] && last != "fetch" && (segs[len(segs)-2] == "axios" || strings.HasPrefix(canon, "axios.")) {
			return sinkSpec{sinkURL, 0}, true
		}
	}
	return sinkSpec{}, false
}

func (f *File) definesFunc(name string) bool {
	for _, fn := range f.Funcs {
		if fn.Name == name {
			return true
		}
	}
	return false
}

// sanitizerBits returns the taint bits a call clears from its arguments and result, and whether
// the callee is a sanitizer at all.
func sanitizerBits(segs []string) (uint8, bool) {
	if len(segs) == 0 {
		return 0, false
	}
	name := segs[len(segs)-1]
	switch name {
	case "parseInt", "parseFloat", "Number", "int", "float", "bool", "Boolean", "len", "isNaN", "Math",
		"encodeURIComponent", "quote_plus", "urlencode", "escape", "hash", "createHash", "uuid4", "randomUUID":
		return tAll, true
	case "quote":
		return tAll, true // shlex.quote, urllib.parse.quote
	case "basename", "secure_filename":
		return tPath, true
	case "shellescape", "escapeShellArg", "escapeshellarg", "shellEscape", "shell_quote", "shq":
		return tCmd, true
	}
	low := strings.ToLower(name)
	if !(strings.Contains(low, "sanitiz") || strings.Contains(low, "validat") || strings.Contains(low, "safe") ||
		strings.Contains(low, "secure") || strings.Contains(low, "allowed") || strings.Contains(low, "escape") ||
		strings.HasPrefix(low, "assert") || strings.HasPrefix(low, "ensure") || strings.HasPrefix(low, "check") ||
		strings.HasPrefix(low, "verify") || strings.HasPrefix(low, "isvalid") || strings.HasPrefix(low, "is_valid")) {
		return 0, false
	}
	var bits uint8
	if strings.Contains(low, "path") || strings.Contains(low, "file") || strings.Contains(low, "dir") || strings.Contains(low, "folder") {
		bits |= tPath
	}
	if strings.Contains(low, "url") || strings.Contains(low, "uri") || strings.Contains(low, "host") || strings.Contains(low, "domain") || strings.Contains(low, "endpoint") {
		bits |= tURL
	}
	if strings.Contains(low, "cmd") || strings.Contains(low, "command") || strings.Contains(low, "shell") || strings.Contains(low, "arg") {
		bits |= tCmd
	}
	if bits == 0 {
		bits = tAll
	}
	return bits, true
}

var reGuardPath = regexp.MustCompile(`^(startsWith|startswith|is_relative_to|relative_to|commonpath|commonprefix|isPathAllowed|isWithin|isInside|isSubPath|isSubpath|realpath|relative|is_within|is_safe_path)$`)
var reGuardWord = regexp.MustCompile(`(?i)(allow|whitelist|permitted|trusted|safe|valid)`)
var reGuardHost = regexp.MustCompile(`^(hostname|host|netloc|origin|protocol|scheme)$`)
