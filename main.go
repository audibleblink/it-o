//go:build aix || freebsd || linux || netbsd || openbsd || solaris || darwin

package main

import (
	"flag"
	"fmt"
	"log"
	"regexp"
	"sync"
)

var (
	// yaraFile string
	pattern      string
	pid          int
	around       int
	only         bool
	embeddedYara bool
	wg           sync.WaitGroup
)

func init() {
	flag.IntVar(&pid, "p", 0, "pid to search")
	flag.StringVar(&pattern, "r", "", "regex pattern to search")
	flag.IntVar(&around, "C", 0, "number of lines to show around the match")
	flag.BoolVar(&only, "o", false, "return only the matching portion")
	flag.BoolVar(&embeddedYara, "Y", false, "use yara rules embedded at buildtime")
	flag.Parse()

	if pid == 0 || (!embeddedYara) {
		flag.Usage()
	}
}

func main() {
	resultsCh := make(chan []*Result)

	// continuously print results as they come in
	go func(ch chan []*Result) {
		for resSlice := range ch {
			if len(resSlice) == 1 {
				fmt.Println(resSlice[0].String())
				continue
			}

			for _, res := range resSlice {
				fmt.Println(res.String())
			}
			fmt.Println("-------")
		}
	}(resultsCh)

	if embeddedYara {

		err := YaraSearch(pid, resultsCh)
		if err != nil {
			log.Fatalln(err)
		}
		wg.Wait()
		return

	} else {

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
}

type Result struct {
	PID    int
	Offset int64
	Match  string

	Name string
}

func (r Result) String() string {
	tmpl := "0x%012x\t%d\t%q\t%s"
	return fmt.Sprintf(tmpl, r.Offset, r.PID, r.Match, r.Name)
}
