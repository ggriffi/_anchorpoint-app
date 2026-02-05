package network

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// getRawMemData is a helper to avoid repeating logic
func getRawMemData() (uint64, uint64) {
	path := "/proc/meminfo"
	if _, err := os.Stat("/host/proc/meminfo"); err == nil {
		path = "/host/proc/meminfo"
	}

	file, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	var total, available uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Only one scanner.Scan() call per loop!
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "MemTotal:":
			total, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemAvailable:":
			available, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return total, available
}

func GetMemStats() string {
	path := "/proc/meminfo"
	if _, err := os.Stat("/host/proc/meminfo"); err == nil {
		path = "/host/proc/meminfo"
	}

	file, err := os.Open(path)
	if err != nil {
		return "Error"
	}
	defer file.Close()

	var total, available uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "MemTotal:":
			total, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemAvailable:":
			available, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}

	if total == 0 {
		return "0 MiB"
	}
	used := (total - available) / 1024
	return fmt.Sprintf("%v MiB", used)
}

func GetMemPercent() float64 {
	total, available := getRawMemData()
	if total == 0 {
		return 0.0
	}
	return (float64(total-available) / float64(total)) * 100
}
