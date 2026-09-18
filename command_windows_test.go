//go:build windows

package main

import (
	"os/exec"
	"testing"
)

func TestConfigureCommandHidesWindows(t *testing.T) {
	cmd := exec.Command("adb", "version")
	configureCommand(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.HideWindow {
		t.Fatal("configureCommand() did not enable HideWindow")
	}
}
