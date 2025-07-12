package mobile

import "fmt"

var apkPath, payload, injectPath string

func InteractInject() {
	fmt.Println("enter apk path: ")
	fmt.Scan(&apkPath)

	fmt.Println("enter payload path: ")
	fmt.Scan(&payload)

	fmt.Println("enter the output path: ")
	fmt.Scan(&injectPath)

	KnifeInjectCLI(apkPath, payload, injectPath)
}
