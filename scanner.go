//go:build aix || freebsd || linux || netbsd || openbsd || solaris || darwin

package main

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/hillu/go-yara/v4"
)

//go:embed rules/*
var YaRule embed.FS

type Line struct {
	pos  int64
	data string
}

func YaraSearch(pid int, resultCh chan []*Result) error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to init YARA parser: %s", err)
	}

	files, err := YaRule.ReadDir("rules")
	if err != nil {
		log.Fatalf("Faild to read embedded rules: %s", err)
	}

	for _, ruleFile := range files {
		ruleBytes, err := YaRule.ReadFile(fmt.Sprintf("rules/%s", ruleFile.Name()))
		if err != nil {
			log.Fatalf("read file: %s", err)
		}

		err = compiler.AddString(string(ruleBytes), "it-o")
		if err != nil {
			fmt.Println(string(ruleBytes))
			log.Fatalf("error adding rule string: %s", err)
		}
	}

	compiledRules, err := compiler.GetRules()
	if err != nil {
		log.Fatal(err)
	}

	var matches yara.MatchRules
	scanner, err := yara.NewScanner(compiledRules)
	if err != nil {
		log.Fatal(err)
	}
	err = scanner.SetCallback(&matches).ScanProc(pid)
	if err != nil {
		log.Fatal(err)
	}

	var results []*Result

	wg.Add(len(matches))
	for _, match := range matches {
		for _, mStr := range match.Strings {

			result := &Result{
				PID:    pid,
				Offset: int64(mStr.Offset),
				Match:  string(mStr.Data),
				Name:   match.Rule,
			}

			results = append(results, result)
			resultCh <- results
		}
		wg.Done()
	}
	return err
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

			line, err := reader.ReadString(0)
			preReadPos := currPos - int64(len(line))
			if err != nil {
				return fmt.Errorf("read of %s at offset 0x%x failed: %s", f.Name(), preReadPos, err)
			}
			// update current position to post-read location
			currPos, _ = f.Seek(0, io.SeekCurrent)

			// remove unprintable chars
			line = printable(line)

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

			// get remaining string when -C was passed
			for i := 0; i < around; i++ {

				line, err := reader.ReadString(0)
				preReadPos := currPos - int64(len(line))
				if err != nil {
					return fmt.Errorf("read of %s at offset 0x%x failed: %s", f.Name(), currPos, err)
				}
				currPos, _ = f.Seek(0, io.SeekCurrent) // update current position

				// remove unprintable chars
				line = printable(line)

				// no need to continue if it's smaller than our pattern
				if len(line) < len(matcher.String()) {
					i -= 1
					continue
				}

				buf = append(buf, &Line{data: line, pos: preReadPos})
			}

			var results []*Result
			for _, r := range buf {
				results = append(results, &Result{pid, r.pos, r.data, ""})
			}
			resultCh <- results
		}
	}

	return nil
}

func printable(in string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, in)
}
