//go:build aix || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
)

func MemSearch(proc Proc, matcher *regexp.Regexp, resultCh chan Result) error {

	f, err := os.Open(proc.fs.Path("mem"))
	if err != nil {
		return fmt.Errorf("failed to open %s: %s", f.Name(), err)
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	var line []byte

	// Iterate through the memory locations passed by caller.
	maps, err := proc.ProcMaps()
	if err != nil {
		return err
	}
	for _, procMap := range maps {
		if procMap == nil {
			continue
		}
		start, end := int64(procMap.StartAddr), int64(procMap.EndAddr)

		// if the section of memory isn't writeable, then there's no
		// user-supplied data there, and we can skip it
		if !procMap.Perms.Write {
			continue
		}

		reader.Reset(f)
		currPos, err := f.Seek(start, io.SeekStart)
		if err != nil {
			return fmt.Errorf("seek of %s failed: %s", f.Name(), err)
		}

		for currPos < end {

			line, err = reader.ReadBytes(0)
			if err != nil {
				return fmt.Errorf("read of %s at offset 0x%x failed: %s", f.Name(), currPos, err)
			}

			// update current position to post-read location
			currPos, _ = f.Seek(0, io.SeekCurrent)

			// no need to regex the line if it's smaller than our pattern
			if len(line) < len(matcher.String()) {
				continue
			}

			matches := matcher.FindAll(line, -1)
			if matches == nil {
				continue
			}
			for _, match := range matches {
				resultCh <- Result{pid, currPos, match}
			}
		}
	}

	return nil
}
