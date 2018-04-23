/*MIT License

Copyright (c) 2018 Станислав (swork91@mail.ru)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

// +build !windows

package main

import (
	"os"
	"os/user"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// It's not "real" fork, but just restarting the app with the same args (except -d). Unfortunately, golang do not support fork fully, so I'll use this code.
func daemonize(args []string, username string, groupname string, detach bool) error {
	lookupUser, err := user.Lookup(username)
	if err != nil {
		return err
	}
	lookupGroup, err := user.LookupGroup(groupname)
	if err != nil {
		return err
	}

	uid, err := strconv.ParseUint(lookupUser.Uid, 10, 32)
	if err != nil {
		return err
	}

	gid, err := strconv.ParseUint(lookupGroup.Gid, 10, 32)
	if err != nil {
		return err
	}

	currentUid := uint32(unix.Getuid())
	currentGid := uint32(unix.Getgid())

	if currentUid == uint32(uid) && currentGid == uint32(gid) {
		return nil
	}

	attr := &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		//Files: []*os.File{os.Stdin, nil, nil},
		//Env: os.Environ(),
		Sys: &syscall.SysProcAttr{
			Noctty: detach,
			Credential: &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(gid),
			},
		},
	}

	runArgs := []string{}
	for _, arg := range os.Args {
		if arg != "-d" {
			runArgs = append(runArgs, arg)
		}
	}

	process, err := os.StartProcess(os.Args[0], runArgs, attr)
	if err != nil {
		return err
	}

	if detach {
		err = process.Release()
		if err != nil {
			return err
		}
	} else {
		process.Wait()
	}

	os.Exit(0)

	return nil
}
