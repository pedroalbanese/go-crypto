
package main

import (
	"github.com/keybase/go-crypto/openpgp"
	"os"
	"fmt"
	"bytes"
	"github.com/keybase/gopass"
)

func main() {
	el, err := openpgp.ReadArmoredKeyRing(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Bad key: %v\n", err)
		os.Exit(2)
	}
	var buf bytes.Buffer
	tty, err := os.Open("/dev/tty")
	if err != nil {
		fmt.Fprint(os.Stderr, "failed to open dev tty: %v", err)
	}
	os.Stdout.Write([]byte("pw> "))
	pw, err := gopass.GetPasswd(int(tty.Fd()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Bad pw collect: %v\n", err)
		os.Exit(2)
	}
	key := el[0]

	err = key.PrivateKey.Decrypt(pw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to unlock primary: %v\n", err)
	}

	for i,subkey := range key.Subkeys {
		err = subkey.PrivateKey.Decrypt(pw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to unlock subkey: %v %d\n", err, i)
		} else {
			fmt.Printf("+ good subkey decryption %d\n", i)
		}
	}

	err = el[0].Serialize(&buf)
	if err != nil {
		fmt.Fprintf(os.Stderr,  "bad serialize: %v\n", err)
		os.Exit(2)
	}
	_, err = openpgp.ReadKeyRing(&buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "second read failed: %v\n", err)
	}
}

