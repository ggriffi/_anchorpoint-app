package network

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// RunIperfClient connects to a remote iperf3 server to test throughput.
func RunIperfClient(ip string) (string, error) {
	// Set a 20-second timeout for the client test (10s test + overhead)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// -c: client mode, -t: 10 second test duration
	cmd := exec.CommandContext(ctx, "iperf3", "-c", ip, "-t", "10")

	out, err := cmd.CombinedOutput()
	if err != nil {
		// Return the output even on error as it often contains diagnostic info
		return string(out), fmt.Errorf("iperf client error: %w", err)
	}

	return string(out), nil
}

// RunIperfServer starts an iperf3 listener that waits for one connection.
func RunIperfServer() (string, error) {
	// 60-second window to wait for a remote client to connect
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// -s: server mode, -1: handle exactly one test then exit automatically
	cmd := exec.CommandContext(ctx, "iperf3", "-s", "-1")

	out, err := cmd.CombinedOutput()
	if err != nil {
		// Check if the error was a simple timeout
		if ctx.Err() == context.DeadlineExceeded {
			return "Iperf server timed out waiting for a connection (60s).", nil
		}
		return string(out), fmt.Errorf("iperf server error: %w", err)
	}

	return string(out), nil
}
