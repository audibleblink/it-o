//go:build aix || freebsd || linux || netbsd || openbsd || solaris || darwin

package main

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestParseDevice(t *testing.T) {
	cases := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"1f:2b", unix.Mkdev(0x1f, 0x2b), false},
		{"1f", 0, true},
		{"zz:zz", 0, true},
	}

	for _, tt := range cases {
		got, err := parseDevice(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseDevice(%q) expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseDevice(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("parseDevice(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseAddress(t *testing.T) {
	cases := []struct {
		in      string
		want    uintptr
		wantErr bool
	}{
		{"7f", uintptr(0x7f), false},
		{"zz", 0, true},
	}

	for _, tt := range cases {
		got, err := parseAddress(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseAddress(%q) expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseAddress(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("parseAddress(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseProcMap(t *testing.T) {
	validLine := "00400000-00452000 r-xp 00000000 08:02 123456 /usr/bin/foo bar"
	pm, err := parseProcMap(validLine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pm.StartAddr != uintptr(0x00400000) {
		t.Errorf("StartAddr = %#x, want %#x", pm.StartAddr, uintptr(0x00400000))
	}
	if pm.EndAddr != uintptr(0x00452000) {
		t.Errorf("EndAddr = %#x, want %#x", pm.EndAddr, uintptr(0x00452000))
	}
	if pm.Perms == nil || !pm.Perms.Read || pm.Perms.Write || !pm.Perms.Execute || !pm.Perms.Private {
		t.Errorf("unexpected permissions: %+v", pm.Perms)
	}
	if pm.Offset != 0 {
		t.Errorf("Offset = %d, want 0", pm.Offset)
	}
	if pm.Dev != unix.Mkdev(0x08, 0x02) {
		t.Errorf("Dev = %v, want %v", pm.Dev, unix.Mkdev(0x08, 0x02))
	}
	if pm.Inode != 123456 {
		t.Errorf("Inode = %d, want 123456", pm.Inode)
	}
	if pm.Pathname != "/usr/bin/foo bar" {
		t.Errorf("Pathname = %q, want %q", pm.Pathname, "/usr/bin/foo bar")
	}

	// truncated line should return an error
	if _, err := parseProcMap("00400000-00452000 r-xp 00000000 08:02"); err == nil {
		t.Error("expected error for truncated line")
	}

	// invalid address should return an error
	if _, err := parseProcMap("zzzz r-xp 00000000 08:02 1"); err == nil {
		t.Error("expected error for invalid address")
	}
}
