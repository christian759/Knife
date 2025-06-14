// 14th june: this recon tool uses the aapt

package mobile

import (
	"exec"
	"fmt"
)

func parseAPKMeat(apkPath string) {
	cmd := exec.Command("aapt", "dump", "badging", apkPath)
	out, _ := cmd.CombinedOutput()
	fmt.Println(string(out))
}
