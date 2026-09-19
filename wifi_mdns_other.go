//go:build !windows

package main

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func listenMDNSUDP() (*net.UDPConn, error) {
	cfg := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sock := int(fd)
			sockErr = unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if sockErr != nil {
				return
			}
			_ = unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	packet, err := cfg.ListenPacket(ctx, "udp4", "0.0.0.0:5353")
	if err != nil {
		return nil, err
	}
	udp, ok := packet.(*net.UDPConn)
	if !ok {
		_ = packet.Close()
		return nil, fmt.Errorf("mDNS listener is not UDP")
	}
	return udp, nil
}
