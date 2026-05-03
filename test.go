// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/gr3mp/r3mp/common/crypto"
)

func main() {
	fmt.Println("Starting ML-KEM-768 functionality test...")
	testMlKem()
}

// testMlKem runs a full cycle: Seed -> Key Object -> Bytes -> Comparison.
func testMlKem() {
	// 1. Generate a random 64-byte seed
	originalSeed, err := crypto.GenerateMlKemSeed768()
	if err != nil {
		log.Fatalf("Seed generation error: %v", err)
	}
	fmt.Printf("1. Seed generated (length: %d bytes)\n", len(originalSeed))

	// 2. Reconstruct the key object from this seed
	dk, err := crypto.GenDecapsulationKey(originalSeed)
	if err != nil {
		log.Fatalf("Key reconstruction error: %v", err)
	}
	fmt.Println("2. DecapsulationKey768 object successfully created")

	// 3. Extract bytes back from the key object
	exportedBytes := crypto.GetKeyBytes(dk)
	fmt.Printf("3. Bytes extracted from object (length: %d bytes)\n", len(exportedBytes))

	// 4. Verify that the original seed and extracted bytes match
	if bytes.Equal(originalSeed, exportedBytes) {
		fmt.Println("SUCCESS: Original seed and extracted bytes are identical!")
	} else {
		fmt.Println("FAILURE: Data mismatch!")
	}

	// 5. Check public key generation
	pubKey := dk.Bytes()
	fmt.Printf("Key (for transmission): %d bytes\n", len(pubKey))
}
