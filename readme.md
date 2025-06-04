# IT-O

Hacky linux memory probe with a grep-like interface for on-the-fly searching.

[![Open in Dev Containers](https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue&logo=visualstudiocode)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/audibleblink/it-o)

```go

ito -p 123 -r '.{20}[D|d]roid.{20}'

123	0x000002645f60	State)({username:"droid",password:""}),t=b(d.
123	0x000002645f60	x)(Xl.Input,{label:"Droid",name:"password", "
...
```

Or use baked-in yara rules to search for multiple things at once.
```go
ito -p 123 -Y

0x00000023dc3a  123  "sql://root:5nqsXpzkK4XNt@172.17.0.4:3306/portal\""        username_and_password_in_uri
0x00000027d5ea  123  "http://jean:VUQUlYblluSn@git.domain.com/jean/api.git"     username_and_password_in_uri
...
```

<img src="ito.webp" />

## Yara

Rules in the `rules` directory are embedded in the resulting binary. Use `-Y`
with `-p <pid>` to scan a running process or with `-f <file>` to scan a file.
For example,

```go
ito -Y -f /path/to/binary
```

Project uses https://github.com/hillu/go-yara go bindings which means CGO.
Deps:
  - automake
  - libtool
  - make
  - gcc
  - pkg-config

```sh
make deps
make ito
```

## Credits

- Procfs code taken from `Prometheus`
  - https://github.com/prometheus/procfs/blob/master/proc_maps.go#L17
- Initial yara rules from  `shhgit`
  - https://github.com/eth0izzle/shhgit
