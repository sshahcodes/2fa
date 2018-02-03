package totp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Totp struct {
	secret  Key
	issuer  string
	accoutn string
}

type Key struct {
	raw    []byte
	digits int
	offset int // offset of counter
}

const counterLen = 20

func (totp *Totp) GenerateTotp() *Totp {

}

func Validate(file string) *Keychain {
	lines := bytes.SplitAfter(data, []byte("\n"))
	offset := 0
	for i, line := range lines {
		lineno := i + 1
		offset += len(line)
		f := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if len(f) == 1 && len(f[0]) == 0 {
			continue
		}
		if len(f) >= 3 && len(f[1]) == 1 && '6' <= f[1][0] && f[1][0] <= '8' {
			var k Key
			name := string(f[0])
			k.digits = int(f[1][0] - '0')
			raw, err := decodeKey(string(f[2]))
			if err == nil {
				k.raw = raw
				if len(f) == 3 {
					c.keys[name] = k
					continue
				}
				if len(f) == 4 && len(f[3]) == counterLen {
					_, err := strconv.ParseUint(string(f[3]), 10, 64)
					if err == nil {
						// Valid counter.
						k.offset = offset - counterLen
						if line[len(line)-1] == '\n' {
							k.offset--
						}
						c.keys[name] = k
						continue
					}
				}
			}
		}
		log.Printf("%s:%d: malformed key", c.file, lineno)
	}
	return c
}

func key() string {
	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	if err != nil {
		fmt.Println(err)
	}
	return base32.StdEncoding.EncodeToString(secret)
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func (c *Keychain) code(name string) string {
	k, ok := c.keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	var code int
	code = totp(k.raw, time.Now(), k.digits)
	return fmt.Sprintf("%0*d", k.digits, code)
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
