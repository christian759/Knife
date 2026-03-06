// 14th june: this recon tool uses the aapt

package mobile

import (
	"fmt"
	"os/exec"
)

func ParseAPKMeat(apkPath string) {
	cmd := exec.Command("aapt", "dump", "badging", apkPath)
	out, _ := cmd.CombinedOutput()
	fmt.Println(string(out))
}
