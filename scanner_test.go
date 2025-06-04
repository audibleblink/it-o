package main

import (
	"os"
	"regexp"
	"testing"
)

func TestRegexSearchFile(t *testing.T) {
	around = 0
	only = false
	tmpDir := t.TempDir()
	path := tmpDir + "/sample.txt"
	err := os.WriteFile(path, []byte("this is mysecret in here"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan []*Result, 1)
	matcher := regexp.MustCompile("mysecret")
	go func() {
		if err := RegexSearchFile(path, matcher, ch); err != nil {
			t.Error(err)
		}
		close(ch)
	}()
	results := <-ch
	if len(results) == 0 {
		t.Fatal("expected result")
	}
	if results[0].Match == "" {
		t.Error("empty match")
	}
}
