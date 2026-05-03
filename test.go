// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

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
