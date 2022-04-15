//go:build aix || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"flag"
	"fmt"
	"log"
	"regexp"
)

var (
	pattern string
	pid     int
)

func init() {
	flag.IntVar(&pid, "pid", 0, "pid to search")
	flag.StringVar(&pattern, "pattern", "", "regex pattern to search")
	flag.Parse()

	if pid == 0 || pattern == "" {
		flag.Usage()
	}
}

type Result struct {
	PID    int
	Offset int64
	Match  []byte
}

func (r Result) String() string {
	tmpl := "%d\t0x%012x\t%s"
	return fmt.Sprintf(tmpl, r.PID, r.Offset, r.Match)
}

func main() {

	resultsCh := make(chan Result)

	go func(ch chan Result) {
		for res := range ch {
			fmt.Println(res.String())
		}
	}(resultsCh)

	procfs, err := NewFS(DefaultProcMountPoint)
	if err != nil {
		log.Fatalln(err)
	}

	proc, err := procfs.Proc(pid)
	if err != nil {
		log.Fatalln(err)
	}

	matcher := regexp.MustCompile(pattern)
	err = MemSearch(proc, matcher, resultsCh)
	if err != nil {
		log.Fatalln(err)
	}
}
