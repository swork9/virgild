// +build !windows
package main

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// It's not "real" fork, but just restarting the app with the same args (except -d). Unfortunately, golang do not support fork fully, so I'll use this code.
func daemonize(args []string, username string, groupname string, detach bool) error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	lookupResult, err := user.Lookup(username)
	if err != nil {
		return err
	}

	if currentUser.Uid == lookupResult.Uid {
		return nil
	}

	uid, err := strconv.ParseUint(lookupResult.Uid, 10, 32)
	if err != nil {
		return err
	}

	gid, err := strconv.ParseUint(lookupResult.Gid, 10, 32)
	if err != nil {
		return err
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
