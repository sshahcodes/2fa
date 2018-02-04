package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode"
)

type Totp struct {
	Secret    string
	Issuer    string
	Account   string
	Algorithm string
	Digits    int
	Peroid    int
}

func Secret() string {
	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	if err != nil {
		fmt.Println(err)
	}

	return base32.StdEncoding.EncodeToString(secret)
}

func GenerateTotp(totp Totp) string {
	issuer := totp.Issuer
	secret := totp.Secret
	account := totp.Account
	algorithm := totp.Algorithm
	digits := totp.Digits
	period := totp.Peroid

	// adhere to key-uri format: otpauth://TYPE/LABEL?PARAMETERS
	// eg: otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
	url := fmt.Sprintf("otpauth://totp/%s:%s?algorithm=%s&&digits=%d&issuer=%s&perior=%d&secret=%s",
		issuer, account, algorithm, digits, issuer, period, secret)
	return url

}

// ValidateTotp validates input code with stored code (stored code can be computed from key stored in database)
func ValidateTotp(inputCode, dbCode string) bool {
	if inputCode == dbCode {
		return true
	} else {
		return false
	}

}

func CalculateTotp(dbcode string) string {

	finalKey, _ := decodeKey(dbcode)
	code := totp(([]byte(finalKey)), time.Now(), 6)

	return fmt.Sprintf("%0*d", 6, code)
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits)
}
