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

	passcode := promptForPasscode()
	if totp.ValidateTotp(passcode, totp.CalculateTotp(secretKey)) == true {
		fmt.Println("valid code")
	} else {
		fmt.Println("invalid code")
	}
}

func promptForPasscode() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Passcode: ")
	text, _ := reader.ReadString('\n')
	return strings.TrimRight(text, "\n")
}
