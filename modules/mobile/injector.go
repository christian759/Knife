// note: this particular tool just injects .dex to the apk
// ❌It won’t auto-run
// ❌ It won’t infect the device
// ❌ It won’t trigger any reverse shell
// ❌ It won’t activate any code unless the APK already has logic to call it

package mobile

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
)

func InjectFileIntoAPK(apkPath, payloadPath, injectPath string) error {
	payloadData, err := ioutil.ReadFile(payloadPath)
	if err != nil {
		return err
	}

	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return err
	}
	defer r.Close()

	outPath := apkPath + ".mod.apk"
	outFile, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	w := zip.NewWriter(outFile)

	// Copy original APK content
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		hdr := f.FileHeader
		hdr.Method = zip.Deflate
		fw, err := w.CreateHeader(&hdr)
		if err != nil {
			return err
		}
		_, err = io.Copy(fw, rc)
		if err != nil {
			return err
		}
	}

	// Inject payload
	fw, err := w.Create(injectPath)
	if err != nil {
		return err
	}
	_, err = io.Copy(fw, bytes.NewReader(payloadData))
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	fmt.Println("[+] Payload injected at:", injectPath)
	fmt.Println("[+] Modified APK saved to:", outPath)
	return nil
}

// SignAPK signs an APK using uber-apk-signer
func SignAPK(apkPath string) error {
	cmd := exec.Command("uber-apk-signer", "-a", apkPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// KnifeInjectCLI wraps the injection and signing logic
func KnifeInjectCLI(apkPath, payloadPath, outputPath string) error {
	fmt.Println("[*] Injecting payload...")
	err := InjectFileIntoAPK(apkPath, payloadPath, outputPath)
	if err != nil {
		return fmt.Errorf("injection failed: %v", err)
	}

	fmt.Println("[*] Signing APK...")
	modApk := apkPath + ".mod.apk"
	err = SignAPK(modApk)
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}

	fmt.Println("[+] Injection complete. Signed APK ready: ", modApk)
	return nil
}
