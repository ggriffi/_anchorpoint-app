package system

import (
	"fmt"
	"runtime"
)

func GetMemStats() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("%v MiB", m.Alloc/1024/1024)
}
