package main

import (
	"fmt"

	"github.com/gr3mp/r3mp/common/crypto"
)

func main() {
	testMlKem()
}

func testMlKem() {
	key, keyByte, err := crypto.GenKeyMlKem()
	fmt.Println(key, keyByte, err)
}
