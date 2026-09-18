//go:build !windows

package main

import "os/exec"

func configureCommand(_ *exec.Cmd) {}
