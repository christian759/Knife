package wifi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CapturePMKID captures on iface for timeout duration and writes readable PMKID lines to outfile.
// The output format: <pmkid_hex>\t<client_mac>\t<ap_mac> (one per line)
//
// Notes:
// - This function prefers hcxdumptool/hcxpcapngtool/hcxpcaptool toolchain if available.
// - If not available, it will try to extract PMKID fields via tshark (discovering a pmkid-related field).
// - The temporary pcapng is left in /tmp/<file> if extraction fails so you can inspect it manually.
// - The caller should run the program with sufficient privileges (sudo or capabilities) or the capture will fail.
func CapturePMKID(iface, outfile string, timeout time.Duration) error {
	if strings.TrimSpace(outfile) == "" {
		return fmt.Errorf("output filename required")
	}
	if strings.TrimSpace(iface) == "" {
		return fmt.Errorf("interface required")
	}

	// Ensure output directory exists
	outDir := filepath.Dir(outfile)
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to ensure output dir: %w", err)
	}

	tmp := fmt.Sprintf("/tmp/knife_capture_%s.pcapng", iface)

	// 1) Capture: prefer hcxdumptool if present, else try tcpdump
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	var captureCmd *exec.Cmd
	if _, err := exec.LookPath("hcxdumptool"); err == nil {
		// hcxdumptool will manage monitor mode itself
		captureCmd = exec.CommandContext(ctx, "hcxdumptool", "-i", iface, "-o", tmp, "--enable_status=0")
	} else if _, err := exec.LookPath("tcpdump"); err == nil {
		// tcpdump requires the interface to already be in monitor mode; less reliable for PMKID extraction
		captureCmd = exec.CommandContext(ctx, "tcpdump", "-i", iface, "-w", tmp)
	} else {
		return errors.New("neither hcxdumptool nor tcpdump found; please install hcxdumptool (recommended) or tcpdump")
	}

	// Start capture
	if err := captureCmd.Start(); err != nil {
		return fmt.Errorf("failed to start capture command: %w", err)
	}

	// Wait for capture to finish or timeout
	done := make(chan error, 1)
	go func() { done <- captureCmd.Wait() }()

	select {
	case <-ctx.Done():
		// timed out — try to kill process
		_ = captureCmd.Process.Kill()
		<-done
	case err := <-done:
		if err != nil {
			// non-zero exit is not fatal for us; the file may still exist
			// record it for diagnostics below
			fmt.Printf("capture exited with: %v (continuing if file exists)\n", err)
		}
	}

	// confirm pcap file exists
	if _, err := os.Stat(tmp); os.IsNotExist(err) {
		return fmt.Errorf("capture file not created: %s", tmp)
	}

	// 2) Extraction: prefer hcxpcapngtool/hcxpcaptool if available
	// Try hcxpcapngtool -o outfile tmp
	if _, err := exec.LookPath("hcxpcapngtool"); err == nil {
		// try -o first (hashcat PMKID output)
		cmd := exec.Command("hcxpcapngtool", "-o", outfile, tmp)
		outB, err := cmd.CombinedOutput()
		if err == nil {
			// success — outfile should now be human-readable hash lines
			return nil
		}

		// fallback: try -E to export PMKID list (older/newer versions differ)
		cmd2 := exec.Command("hcxpcapngtool", "-E", outfile, tmp)
		outB2, err2 := cmd2.CombinedOutput()
		if err2 == nil {
			return nil
		}

		// both attempts failed — include output from attempts in error
		return fmt.Errorf("hcxpcapngtool extraction failed:\n-o output: %s\n-E output: %s", string(outB), string(outB2))
	}

	// 3) Next fallback: try tshark if available. We attempt to dynamically find a pmkid-like field name.
	if _, err := exec.LookPath("tshark"); err == nil {
		// find any field name containing "pmkid" (case-insensitive)
		fieldsCmd := exec.Command("tshark", "-G", "fields")
		fieldsOut, err := fieldsCmd.Output()
		if err != nil {
			return fmt.Errorf("failed to list tshark fields: %w (capture at %s)", err, tmp)
		}
		fieldLines := strings.Split(string(fieldsOut), "\n")
		var pmkidField string
		for _, ln := range fieldLines {
			// each line format: name<TAB>... ; we'll check the name (first token)
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			parts := strings.SplitN(ln, "\t", 2)
			name := parts[0]
			if strings.Contains(strings.ToLower(name), "pmkid") {
				pmkidField = name
				break
			}
		}

		// if no pmkid-like field discovered, try common known field names as last resort
		if pmkidField == "" {
			candidates := []string{"wlan_rsna_pmkid", "rsn_pmkid", "wlan.rsn.pmkid"}
			for _, c := range candidates {
				// verify by attempting to run tshark with the field (quiet check)
				checkCmd := exec.Command("tshark", "-r", tmp, "-T", "fields", "-e", c, "-c", "1")
				if _out, _ := checkCmd.CombinedOutput(); _out != nil {
					// if command executed (even if output empty), assume field exists
					// but we should ensure no "Some fields aren't valid" error; so check error
					if err := checkCmd.Run(); err == nil {
						pmkidField = c
						break
					}
				}
			}
		}

		if pmkidField == "" {
			// leave raw capture for manual inspection
			return fmt.Errorf("tshark does not expose a pmkid field on this system; capture saved to %s for manual inspection", tmp)
		}

		// Now extract using the discovered pmkidField plus station and bssid
		tsharkCmd := exec.Command("tshark", "-r", tmp, "-T", "fields", "-e", pmkidField, "-e", "wlan.sa", "-e", "wlan.bssid")
		outBytes, err := tsharkCmd.CombinedOutput()
		if err != nil {
			// include stdout/stderr from tshark for debugging and leave tmp for inspection
			return fmt.Errorf("tshark extraction failed using field '%s': %v\noutput: %s\ncapture: %s", pmkidField, err, string(outBytes), tmp)
		}

		// Clean up output: remove empty lines
		lines := strings.Split(string(outBytes), "\n")
		var keep []string
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				// normalize separators to tabs
				keep = append(keep, strings.Join(strings.Fields(l), "\t"))
			}
		}
		final := strings.Join(keep, "\n")
		if err := os.WriteFile(outfile, []byte(final), 0644); err != nil {
			return fmt.Errorf("failed to write outfile: %w", err)
		}
		// success
		return nil
	}

	// no extractor tools found — report location of raw file
	return fmt.Errorf("no extraction tools (hcxpcapngtool or tshark) found; raw capture saved to %s", tmp)
}
