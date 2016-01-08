
package main

import (
	"github.com/keybase/go-crypto/openpgp"
	"os"
	"fmt"
)

func main() {
	_, err := openpgp.ReadArmoredKeyRing(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Bad key: %v", err)
		os.Exit(2)
	}
}

