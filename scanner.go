//go:build aix || freebsd || linux || netbsd || openbsd || solaris || darwin

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type Line struct {
	pos  int64
	data string
}

func MemSearch(proc Proc, matcher *regexp.Regexp, resultCh chan []*Result) error {

	f, err := os.Open(proc.fs.Path("mem"))
	if err != nil {
		return fmt.Errorf("failed to open %s: %s", f.Name(), err)
	}
	defer f.Close()

	reader := bufio.NewReader(f)

	// Iterate through the memory locations passed by caller.
	maps, err := proc.ProcMaps()
	if err != nil {
		return err
	}

	for _, procMap := range maps {
		if procMap == nil || procMap.Pathname != "[heap]" {
			continue
		}

		reader.Reset(f)

		start, end := int64(procMap.StartAddr), int64(procMap.EndAddr)

		currPos, err := f.Seek(start, io.SeekStart)
		if err != nil {
			return fmt.Errorf("seek of %s failed: %s", f.Name(), err)
		}

		buf := make([]*Line, around*2+1, around*2+1)
		for currPos < end {

			preReadPos, _ := f.Seek(0, io.SeekCurrent)
			line, err := reader.ReadString(0)
			if err != nil {
				return fmt.Errorf("read of %s at offset 0x%x failed: %s", f.Name(), preReadPos, err)
			}
			// update current position to post-read location
			currPos, _ = f.Seek(0, io.SeekCurrent)

			// no need to continue if it's smaller than our pattern
			if len(line) < len(matcher.String()) {
				continue
			}

			res := &Line{data: line, pos: preReadPos}
			matches := matcher.FindAllString(line, -1)

			// no matches; next string
			if matches == nil {
				buf = append(buf[1:], res)
				continue
			}

			if only {
				res.data = strings.Join(matches, " | ")
			}

			// append result, while cropping out oldest string
			buf = append(buf[around+1:], res)

			for i := 0; i < around; i++ {
				preReadPos, _ := f.Seek(0, io.SeekCurrent)
				line, err := reader.ReadString(0)
				if err != nil {
					return fmt.Errorf("read of %s at offset 0x%x failed: %s", f.Name(), currPos, err)
				}
				currPos, _ = f.Seek(0, io.SeekCurrent) // update current position
				res := &Line{data: line, pos: preReadPos}
				buf = append(buf, res)
			}

			var results []*Result
			for _, r := range buf {
				results = append(results, &Result{pid, r.pos, r.data})
			}
			resultCh <- results
		}
	}

	return nil
}
