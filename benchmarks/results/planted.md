| Category | Language | Tier | Tool | Recall | FPR on safe look-alikes | TP / FN / FP / TN |
|---|---|---|---|---:|---:|---|
| command-injection | py | hard | mcpscan | 0.000 | 0.250 | 0 / 2 / 2 / 6 |
| command-injection | py | hard | semgrep 1.184.0 | 0.500 | 0.375 | 1 / 1 / 3 / 5 |
| command-injection | py | hard | bandit 1.9.4 | 0.500 | 1.000 | 1 / 1 / 8 / 0 |
| command-injection | py | standard | mcpscan | 1.000 | 0.000 | 27 / 0 / 0 / 18 |
| command-injection | py | standard | semgrep 1.184.0 | 0.704 | 0.444 | 19 / 8 / 8 / 10 |
| command-injection | py | standard | bandit 1.9.4 | 1.000 | 0.833 | 27 / 0 / 15 / 3 |
| command-injection | ts | hard | mcpscan | 0.000 | 0.273 | 0 / 2 / 3 / 8 |
| command-injection | ts | hard | semgrep 1.184.0 | 0.500 | 0.182 | 1 / 1 / 2 / 9 |
| command-injection | ts | standard | mcpscan | 1.000 | 0.042 | 36 / 0 / 1 / 23 |
| command-injection | ts | standard | semgrep 1.184.0 | 0.500 | 0.375 | 18 / 18 / 9 / 15 |
| path-traversal | py | hard | mcpscan | 0.500 | 0.250 | 1 / 1 / 2 / 6 |
| path-traversal | py | hard | semgrep 1.184.0 | 0.000 | 0.000 | 0 / 2 / 0 / 8 |
| path-traversal | py | hard | bandit 1.9.4 | 0.000 | 0.000 | 0 / 2 / 0 / 8 |
| path-traversal | py | standard | mcpscan | 1.000 | 0.000 | 27 / 0 / 0 / 21 |
| path-traversal | py | standard | semgrep 1.184.0 | 0.000 | 0.000 | 0 / 27 / 0 / 21 |
| path-traversal | py | standard | bandit 1.9.4 | 0.000 | 0.000 | 0 / 27 / 0 / 21 |
| path-traversal | ts | hard | mcpscan | 0.000 | 0.273 | 0 / 2 / 3 / 8 |
| path-traversal | ts | hard | semgrep 1.184.0 | 0.000 | 0.000 | 0 / 2 / 0 / 11 |
| path-traversal | ts | standard | mcpscan | 1.000 | 0.036 | 36 / 0 / 1 / 27 |
| path-traversal | ts | standard | semgrep 1.184.0 | 0.000 | 0.000 | 0 / 36 / 0 / 28 |
| secrets | py | standard | mcpscan | 1.000 | 0.000 | 10 / 0 / 0 / 8 |
| secrets | py | standard | semgrep 1.184.0 | 1.000 | 0.250 | 10 / 0 / 2 / 6 |
| secrets | py | standard | bandit 1.9.4 | 0.900 | 0.625 | 9 / 1 / 5 / 3 |
| secrets | ts | standard | mcpscan | 1.000 | 0.000 | 10 / 0 / 0 / 8 |
| secrets | ts | standard | semgrep 1.184.0 | 1.000 | 0.250 | 10 / 0 / 2 / 6 |
| ssrf | py | hard | mcpscan | 1.000 | 0.250 | 1 / 0 / 2 / 6 |
| ssrf | py | hard | semgrep 1.184.0 | 0.000 | 0.125 | 0 / 1 / 1 / 7 |
| ssrf | py | hard | bandit 1.9.4 | 0.000 | 0.250 | 0 / 1 / 2 / 6 |
| ssrf | py | standard | mcpscan | 1.000 | 0.000 | 27 / 0 / 0 / 21 |
| ssrf | py | standard | semgrep 1.184.0 | 0.259 | 0.238 | 7 / 20 / 5 / 16 |
| ssrf | py | standard | bandit 1.9.4 | 0.259 | 0.286 | 7 / 20 / 6 / 15 |
| ssrf | ts | hard | mcpscan | 1.000 | 0.273 | 1 / 0 / 3 / 8 |
| ssrf | ts | hard | semgrep 1.184.0 | 0.000 | 0.000 | 0 / 1 / 0 / 11 |
| ssrf | ts | standard | mcpscan | 1.000 | 0.036 | 36 / 0 / 1 / 27 |
| ssrf | ts | standard | semgrep 1.184.0 | 0.000 | 0.000 | 0 / 36 / 0 / 28 |
