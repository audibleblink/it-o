// Copyright 2019 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//go:build aix || freebsd || linux || netbsd || openbsd || solaris || darwin

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// DefaultProcMountPoint is the common mount point of the proc filesystem.
	DefaultProcMountPoint = "/proc"
)

// ProcMapPermissions contains permission settings read from `/proc/[pid]/maps`.
type ProcMapPermissions struct {
	// mapping has the [R]ead flag set
	Read bool
	// mapping has the [W]rite flag set
	Write bool
	// mapping has the [X]ecutable flag set
	Execute bool
	// mapping has the [S]hared flag set
	Shared bool
	// mapping is marked as [P]rivate (copy on write)
	Private bool
}

// ProcMap contains the process memory-mappings of the process
// read from `/proc/[pid]/maps`.
type ProcMap struct {
	// The start address of current mapping.
	StartAddr uintptr
	// The end address of the current mapping
	EndAddr uintptr
	// The permissions for this mapping
	Perms *ProcMapPermissions
	// The current offset into the file/fd (e.g., shared libs)
	Offset int64
	// Device owner of this mapping (major:minor) in Mkdev format.
	Dev uint64
	// The inode of the device above
	Inode uint64
	// The file or psuedofile (or empty==anonymous)
	Pathname string
}

// parseDevice parses the device token of a line and converts it to a dev_t
// (mkdev) like structure.
func parseDevice(s string) (uint64, error) {
	toks := strings.Split(s, ":")
	if len(toks) < 2 {
		return 0, fmt.Errorf("unexpected number of fields")
	}

	major, err := strconv.ParseUint(toks[0], 16, 0)
	if err != nil {
		return 0, err
	}

	minor, err := strconv.ParseUint(toks[1], 16, 0)
	if err != nil {
		return 0, err
	}

	return unix.Mkdev(uint32(major), uint32(minor)), nil
}

// parseAddress converts a hex-string to a uintptr.
func parseAddress(s string) (uintptr, error) {
	a, err := strconv.ParseUint(s, 16, 0)
	if err != nil {
		return 0, err
	}

	return uintptr(a), nil
}

// parseAddresses parses the start-end address.
func parseAddresses(s string) (uintptr, uintptr, error) {
	toks := strings.Split(s, "-")
	if len(toks) < 2 {
		return 0, 0, fmt.Errorf("invalid address")
	}

	saddr, err := parseAddress(toks[0])
	if err != nil {
		return 0, 0, err
	}

	eaddr, err := parseAddress(toks[1])
	if err != nil {
		return 0, 0, err
	}

	return saddr, eaddr, nil
}

// parsePermissions parses a token and returns any that are set.
func parsePermissions(s string) (*ProcMapPermissions, error) {
	if len(s) < 4 {
		return nil, fmt.Errorf("invalid permissions token")
	}

	perms := ProcMapPermissions{}
	for _, ch := range s {
		switch ch {
		case 'r':
			perms.Read = true
		case 'w':
			perms.Write = true
		case 'x':
			perms.Execute = true
		case 'p':
			perms.Private = true
		case 's':
			perms.Shared = true
		}
	}

	return &perms, nil
}

// parseProcMap will attempt to parse a single line within a proc/[pid]/maps
// buffer.
func parseProcMap(text string) (*ProcMap, error) {
	fields := strings.Fields(text)
	if len(fields) < 5 {
		return nil, fmt.Errorf("truncated procmap entry")
	}

	saddr, eaddr, err := parseAddresses(fields[0])
	if err != nil {
		return nil, err
	}

	perms, err := parsePermissions(fields[1])
	if err != nil {
		return nil, err
	}

	offset, err := strconv.ParseInt(fields[2], 16, 0)
	if err != nil {
		return nil, err
	}

	device, err := parseDevice(fields[3])
	if err != nil {
		return nil, err
	}

	inode, err := strconv.ParseUint(fields[4], 10, 0)
	if err != nil {
		return nil, err
	}

	pathname := ""

	if len(fields) >= 5 {
		pathname = strings.Join(fields[5:], " ")
	}

	return &ProcMap{
		StartAddr: saddr,
		EndAddr:   eaddr,
		Perms:     perms,
		Offset:    offset,
		Dev:       device,
		Inode:     inode,
		Pathname:  pathname,
	}, nil
}

type Proc struct {
	PID int
	fs  FS
}

// NewProc returns a process for the given pid under /proc.
func NewProc(pid int) (Proc, error) {
	fs, err := NewFS(DefaultProcMountPoint)
	if err != nil {
		return Proc{}, err
	}
	return fs.Proc(pid)
}

// ProcMaps reads from /proc/[pid]/maps to get the memory-mappings of the
// process.
func (p Proc) ProcMaps() ([]*ProcMap, error) {
	var maps = make([]*ProcMap, 1)
	file, err := os.Open(p.fs.Path("maps"))
	if err != nil {
		return maps, err
	}
	defer file.Close()

	scan := bufio.NewScanner(file)
	for scan.Scan() {
		m, err := parseProcMap(scan.Text())
		if err != nil {
			return maps, err
		}

		maps = append(maps, m)
	}
	return maps, nil
}

// FS represents a pseudo-filesystem, normally /proc or /sys, which provides an
// interface to kernel data structures.
type FS string

// NewFS returns a new FS mounted under the given mountPoint. It will error
// if the mount point can't be read.
func NewFS(mountPoint string) (FS, error) {
	info, err := os.Stat(mountPoint)
	if err != nil {
		return "", fmt.Errorf("could not read %q: %w", mountPoint, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("mount point %q is not a directory", mountPoint)
	}

	return FS(mountPoint), nil
}

// Path appends the given path elements to the filesystem path, adding separators
// as necessary.
func (fs FS) Path(p ...string) string {
	return filepath.Join(append([]string{string(fs)}, p...)...)
}

func (fs FS) Proc(pid int) (Proc, error) {
	path := fs.Path(strconv.Itoa(pid))
	if _, err := os.Stat(path); err != nil {
		return Proc{}, err
	}
	return Proc{PID: pid, fs: FS(path)}, nil
}
