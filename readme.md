# IT-O

Hacky linux memory probe. 

```
ito -p 123 -r '.{20}[D|d]roid.{20}'

123	0x000002645f60	State)({username:"droid",password:""}),t=b(d.
123	0x000002645f60	x)(Xl.Input,{label:"Droid",name:"password", "
...
```

## Credits

- Procfs code taken from `Prometheus`
  - https://github.com/prometheus/procfs/blob/master/proc_maps.go#L17
