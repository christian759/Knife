package mobile

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"time"
)

func getProcesses() (map[string]bool, error) {
	cmd := exec.Command("adb", "shell", "ps", "-A")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	procMap := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		procMap[line] = true
	}

	return procMap, nil
}

func Monitor() {
	prevProcs, err := getProcesses()
	if err != nil {
		panic(err)
	}

	for {
		time.Sleep(1 * time.Second)

		currProcs, err := getProcesses()
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		// Print new processes
		for line := range currProcs {
			if !prevProcs[line] {
				fmt.Println("New process:", line)
			}
		}

		// Print stopped processes
		for line := range prevProcs {
			if !currProcs[line] {
				fmt.Println("Stopped process:", line)
			}
		}

		prevProcs = currProcs
	}
}
