package mobile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// BackupConfig holds Android backup configuration
type BackupConfig struct {
	PackageName string
	OutputPath  string
	IncludeAPK  bool
	IncludeOBB  bool
	AllData     bool
}

// CreateBackup creates an Android backup via ADB
func CreateBackup(config BackupConfig) error {
	devices, err := GetConnectedDevices()
	if err != nil {
		return fmt.Errorf("failed to get devices: %v", err)
	}

	if len(devices) == 0 {
		return fmt.Errorf("no Android devices connected via ADB")
	}

	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║           ANDROID BACKUP EXTRACTOR                         ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Printf("Device: %s\n", devices[0])
	fmt.Printf("Package: %s\n", config.PackageName)
	fmt.Println(strings.Repeat("─", 60))

	// Build backup command
	args := []string{"backup"}
	
	if config.IncludeAPK {
		args = append(args, "-apk")
	} else {
		args = append(args, "-noapk")
	}

	if config.IncludeOBB {
		args = append(args, "-obb")
	} else {
		args = append(args, "-noobb")
	}

	if config.AllData {
		args = append(args, "-all")
	}

	args = append(args, "-f", config.OutputPath, config.PackageName)

	fmt.Println("\n📦 Creating backup...")
	fmt.Println("⚠️  You may need to confirm backup on device (unlock screen)")
	fmt.Println("⚠️  Enter backup password if prompted (or leave blank)")
	
	cmd := exec.Command("adb", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("backup failed: %v", err)
	}

	// Check if file was created
	if _, err := os.Stat(config.OutputPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file was not created - user may have cancelled")
	}

	fileInfo, _ := os.Stat(config.OutputPath)
	fmt.Printf("\n✓ Backup created: %s\n", config.OutputPath)
	fmt.Printf("  Size: %.2f MB\n", float64(fileInfo.Size())/1024/1024)

	return nil
}

// ExtractBackup extracts .ab backup to .tar format
func ExtractBackup(backupFile string) (string, error) {
	// Check if backup exists
	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		return "", fmt.Errorf("backup file not found: %s", backupFile)
	}

	fmt.Println("\n📂 Extracting backup...")

	// Output tar file
	tarFile := strings.TrimSuffix(backupFile, ".ab") + ".tar"

	// Android backup format: 24 byte header + zlib compressed tar
	// We'll use dd to skip header and openssl/python to decompress

	// Method 1: Using dd and openssl (most common)
	fmt.Println("  Method: dd + openssl (or python zlib)")
	
	// Skip first 24 bytes and decompress
	cmd := exec.Command("sh", "-c", 
		fmt.Sprintf("dd if=%s bs=24 skip=1 | openssl zlib -d > %s", 
			backupFile, tarFile))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try alternative method with python
		fmt.Println("  Trying alternative method with Python...")
		pythonScript := fmt.Sprintf(`
import zlib
with open('%s', 'rb') as f:
    f.read(24)  # skip header
    data = f.read()
with open('%s', 'wb') as f:
    f.write(zlib.decompress(data))
`, backupFile, tarFile)
		
		cmd = exec.Command("python3", "-c", pythonScript)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("extraction failed: %v\nOutput: %s", err, output)
		}
	}

	fmt.Printf("✓ Extracted to: %s\n", tarFile)
	
	return tarFile, nil
}

// ListBackupContents lists files in the extracted backup
func ListBackupContents(tarFile string) error {
	if _, err := os.Stat(tarFile); os.IsNotExist(err) {
		return fmt.Errorf("tar file not found: %s", tarFile)
	}

	fmt.Println("\n📋 Backup Contents:")
	fmt.Println(strings.Repeat("─", 60))

	cmd := exec.Command("tar", "-tzf", tarFile)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list tar contents: %v", err)
	}

	files := strings.Split(string(output), "\n")
	
	// Categorize files
	databases := []string{}
	sharedPrefs := []string{}
	otherFiles := []string{}

	for _, file := range files {
		if file == "" {
			continue
		}
		
		if strings.Contains(file, "databases/") {
			databases = append(databases, file)
		} else if strings.Contains(file, "shared_prefs/") {
			sharedPrefs = append(sharedPrefs, file)
		} else {
			otherFiles = append(otherFiles, file)
		}
	}

	if len(databases) > 0 {
		fmt.Printf("\n🗄️  Databases (%d):\n", len(databases))
		for _, db := range databases {
			fmt.Printf("   • %s\n", filepath.Base(db))
		}
	}

	if len(sharedPrefs) > 0 {
		fmt.Printf("\n⚙️  Shared Preferences (%d):\n", len(sharedPrefs))
		for _, pref := range sharedPrefs {
			fmt.Printf("   • %s\n", filepath.Base(pref))
		}
	}

	if len(otherFiles) > 0 {
		fmt.Printf("\n📄 Other Files (%d):\n", len(otherFiles))
		displayed := 0
		for _, file := range otherFiles {
			if displayed < 20 { // Limit display
				fmt.Printf("   • %s\n", file)
				displayed++
			}
		}
		if len(otherFiles) > 20 {
			fmt.Printf("   ... and %d more files\n", len(otherFiles)-20)
		}
	}

	fmt.Printf("\nTotal files: %d\n", len(files)-1)
	
	return nil
}

// ExtractFileFromBackup extracts a specific file from the backup
func ExtractFileFromBackup(tarFile, targetFile, outputDir string) error {
	if _, err := os.Stat(tarFile); os.IsNotExist(err) {
		return fmt.Errorf("tar file not found: %s", tarFile)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	fmt.Printf("Extracting: %s\n", targetFile)
	
	cmd := exec.Command("tar", "-xzf", tarFile, "-C", outputDir, targetFile)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract file: %v", err)
	}

	extractedPath := filepath.Join(outputDir, targetFile)
	fmt.Printf("✓ Extracted to: %s\n", extractedPath)
	
	return nil
}

// AnalyzeBackupSecurity performs security analysis on backup contents
func AnalyzeBackupSecurity(tarFile string) error {
	fmt.Println("\n🔍 Security Analysis:")
	fmt.Println(strings.Repeat("─", 60))

	cmd := exec.Command("tar", "-tzf", tarFile)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to read tar: %v", err)
	}

	files := strings.Split(string(output), "\n")
	issues := []string{}

	// Check for sensitive files
	for _, file := range files {
		if strings.Contains(file, ".db") || strings.Contains(file, ".sqlite") {
			issues = append(issues, fmt.Sprintf("Database file found: %s (may contain sensitive data)", filepath.Base(file)))
		}
		if strings.Contains(file, "shared_prefs") && (strings.Contains(file, "auth") || 
			strings.Contains(file, "token") || strings.Contains(file, "session")) {
			issues = append(issues, fmt.Sprintf("Potential credentials in: %s", filepath.Base(file)))
		}
		if strings.Contains(file, ".key") || strings.Contains(file, ".pem") {
			issues = append(issues, fmt.Sprintf("Cryptographic key file: %s", filepath.Base(file)))
		}
	}

	if len(issues) > 0 {
		fmt.Println("⚠️  Potential Security Issues Found:")
		for i, issue := range issues {
			if i < 10 { // Limit display
				fmt.Printf("   %d. %s\n", i+1, issue)
			}
		}
		if len(issues) > 10 {
			fmt.Printf("   ... and %d more issues\n", len(issues)-10)
		}
	} else {
		fmt.Println("✓ No obvious security issues detected")
		fmt.Println("  (Manual review still recommended)")
	}

	fmt.Println("\n💡 Recommended Actions:")
	fmt.Println("   • Extract and examine database files with SQLite browser")
	fmt.Println("   • Review shared_prefs XML files for hardcoded credentials")
	fmt.Println("   • Check for unencrypted sensitive data")
	fmt.Println("   • Verify proper data encryption is implemented")

	return nil
}
