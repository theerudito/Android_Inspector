package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestStartupBootstrapsADBOnceAndDoesNotBlockOnFailure(t *testing.T) {
	tests := []struct {
		name     string
		runError error
	}{
		{name: "successful startup"},
		{name: "failed startup", runError: errors.New("adb unavailable")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			client := &ADBClient{
				adbPath: "adb",
				run: func(_ context.Context, name string, args ...string) ([]byte, error) {
					calls++
					if name != "adb" || !reflect.DeepEqual(args, []string{"start-server"}) {
						t.Fatalf("unexpected startup command: %s %#v", name, args)
					}
					return nil, tt.runError
				},
			}
			app := &App{client: client}

			app.startup(context.Background())
			app.startup(context.Background())

			if calls != 1 {
				t.Fatalf("startup invoked ADB %d times, want 1", calls)
			}
		})
	}
}

func TestListDevicesDoesNotBootstrapADB(t *testing.T) {
	var commands [][]string
	client := &ADBClient{
		adbPath: "adb",
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, append([]string{name}, args...))
			return []byte("List of devices attached\nABC123\tunauthorized\n"), nil
		},
	}

	devices, err := client.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(devices, []Device{{Serial: "ABC123", State: "unauthorized"}}) {
		t.Fatalf("ListDevices() = %#v", devices)
	}
	want := [][]string{{"adb", "devices", "-l"}}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %#v, want %#v", commands, want)
	}
}
