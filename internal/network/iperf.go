package network

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// RunIperfClient connects to a remote iperf3 server
func RunIperfClient(ip string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// -c: client mode, -t: time (10s), -J: JSON output (optional, remove for raw text)
	cmd := exec.CommandContext(ctx, "iperf3", "-c", ip, "-t", "10")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("iperf client error: %w", err)
	}
	return string(out), nil
}

// RunIperfServer starts an iperf3 listener for one test then exits
func RunIperfServer() (string, error) {
	// Longer timeout for server mode to wait for a connection
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// -s: server mode, -1: handle one client then exit
	cmd := exec.CommandContext(ctx, "iperf3", "-s", "-1")
	out, err := cmd.CombinedOutput()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "Iperf server timed out waiting for a connection.", nil
		}
		return string(out), fmt.Errorf("iperf server error: %w", err)
	}
	return string(out), nil
}
