# IT-O

Hacky linux memory probe. 

```
memscan -pid 123 -pattern '.{20}[D|d]roid.{20}'

123	0x000002645f60	State)({username:"droid",password:""}),t=b(d.
123	0x000002645f60	x)(Xl.Input,{label:"Droid",name:"password", "
...
```

## Credits

- Memory searching taken from `sysbox-fs`
  - https://github.com/nestybox/sysbox-fs/blob/master/seccomp/memParserProcfs.go#L35
- Procfs code taken from `Prometheus`
  - https://github.com/prometheus/procfs/blob/master/proc_maps.go#L17
