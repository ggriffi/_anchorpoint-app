package network

import (
	"fmt"
	"runtime"
)

// GetMemPercent calculates current memory usage as a percentage
func GetMemPercent() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if m.Sys == 0 {
		return 0
	}

	// Returns the percentage of heap memory relative to total system-reserved memory
	return (float64(m.Alloc) / float64(m.Sys)) * 100
}

// GetMemStats returns a formatted string for the dashboard header
func GetMemStats() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("%v MiB", m.Alloc/1024/1024)
}
