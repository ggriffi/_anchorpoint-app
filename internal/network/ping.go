package network

import (
	"os/exec"
	"runtime"
	"strings"
)

// sanitize replaces internal infrastructure IPs with generic labels
func sanitize(output string) string {
	// Define the internal IPs found in your traceroute
	internalIPs := map[string]string{
		"10.17.30.1":    "REDACTED-GW",
		"192.168.1.254": "REDACTED-MODEM",
	}

	sanitized := output
	for raw, redacted := range internalIPs {
		sanitized = strings.ReplaceAll(sanitized, raw, redacted)
	}
	return sanitized
}

// Ping checks if a host is reachable.
func Ping(host string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "2000", host)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "2", host)
	}
	err := cmd.Run()
	return err == nil
}

// Traceroute executes a standard traceroute and sanitizes the output.
func Traceroute(host string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// -d prevents DNS lookups on Windows
		cmd = exec.Command("tracert", "-d", host)
	} else {
		// -n: No DNS (Speed)
		// -w 1: 1 second timeout per hop
		// -q 1: Only 1 probe per hop instead of 3 (Efficiency)
		cmd = exec.Command("traceroute", "-n", "-w", "1", "-q", "1", "-I", host)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return sanitize(string(out)), nil
}

// MTR executes an MTR report and sanitizes the output.
func MTR(host string) (string, error) {
	// -r: report mode, -c 5: 5 cycles, -n: no DNS
	cmd := exec.Command("mtr", "-r", "-c", "5", "-n", host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return sanitize(string(out)), nil
}

// RunIperf ensures we are the client pushing to a remote destination
func RunIperf(server string) (string, error) {
	// Use the 'server' variable instead of the hard-coded IP
	cmd := exec.Command("iperf3", "-c", server, "-p", "5201", "-t", "5", "-R")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func RunSpeedtest() (string, error) {
	// --secure is vital in containers to avoid 403 blocks
	// --json can also be used if you want to parse the data later for your dashboard
	cmd := exec.Command("speedtest-cli", "--simple", "--secure")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "Speedtest Error: " + string(out), err
	}
	return string(out), nil
}
