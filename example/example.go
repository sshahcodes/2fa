package main

import (
	"fmt"
	"io/ioutil"

	totp "github.com/sshahcodes/2fa"

	"rsc.io/qr"
)

func main() {
	// get secret key
	secretKey := totp.Secret()

	// Now is perfect time to dynamically fetch user names or storing secret key into database

	// get key-uri
	key := totp.GenerateTotp(totp.Totp{
		Secret:    secretKey,
		Issuer:    "authix",
		Account:   "test@authix.com",
		Algorithm: "SHA1",
		Digits:    6,
		Peroid:    30,
	})

	//generate qr image with rsc.io/qr
	image, err := qr.Encode(key, qr.Q)
	if err != nil {
		fmt.Println(err)
	}

	// write qr.png to directory
	err = ioutil.WriteFile("qr.png", image.PNG(), 0644)
	if err != nil {
		panic(err)
	}

}
