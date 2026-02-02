package system

import (
	"os/exec"
)

// GetDockerContainers runs 'docker ps' to get a list of active containers
func GetDockerContainers() string {
	// Logic: -a for all, or remove for only running.
	// --format makes it clean for a web dashboard.
	cmd := exec.Command("docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Image}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "Docker service not responding or permissions issue."
	}
	return string(out)
}
