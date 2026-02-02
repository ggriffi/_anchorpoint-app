package network

import (
	"io"
	"net/http"
	"strings"
	"time"
)

func GetPublicIP() string {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(body))
}
