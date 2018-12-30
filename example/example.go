/*
This example generetes key-uri and qr code and asks for 6 digit code to validate.
qr code will be generated in you current db. you can use google authenticator to scan
and validate the code. Have fun!
*/
package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/sshahcodes/totp"

	"rsc.io/qr"
)

func main() {
	secretKey := totp.Secret()
	fmt.Printf("secret key generated was: %s\n", secretKey)

	key := totp.GenerateTotp(totp.Totp{
		Secret:    secretKey,
		Issuer:    "authix",
		Account:   "test@authix.com",
		Algorithm: "SHA1",
		Digits:    6,
		Peroid:    30,
	})

	fmt.Println(key)

	image, err := qr.Encode(key, qr.Q)
	if err != nil {
		fmt.Println(err)
	}

	err = ioutil.WriteFile("qr.png", image.PNG(), 0644)
	if err != nil {
		panic(err)
	}

	for {
		inputCode := prompt()
		fmt.Println(inputCode)
		totpThen, totpNow, totpAfter := totp.CalculateTotp(secretKey)

		if totp.ValidateTotp(inputCode, totpThen) == true || totp.ValidateTotp(inputCode, totpNow) == true || totp.ValidateTotp(inputCode, totpAfter) == true {
			fmt.Println("valid code")
		} else {
			fmt.Println("invalid code")
		}

		// if totp.ValidateTotp(inputCode, tot)
		fmt.Println(totpThen, totpNow, totpAfter)
	}

	// if totp.ValidateTotp(inputCode, totp.CalculateTotp(secretKey)) == true {
	// 	fmt.Println("valid code")
	// } else {
	// 	fmt.Println("invalid code")
	// }

}

func prompt() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Passcode: ")
	code, _ := reader.ReadString('\n')
	return strings.TrimRight(code, "\n")
}
