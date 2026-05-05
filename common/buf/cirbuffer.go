// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package buf

import (
	"errors"
	// "io"
	"sync"
)

// Implementation of a ring buffer

var (
	ErrBufferFull  = errors.New("buffer is full")
	ErrBufferEmpty = errors.New("buffer is empty")
)

type cirbuf struct {
	data     []byte     // Data (slice bytes).
	readPtr  uint32     // The index from which the buffer reading begins.
	writePtr uint32     // The index at which writing to the buffer begins.
	size     uint32     // The current amount of data in the buffer.
	capacity uint32     // Total size of the array.
	mu       sync.Mutex // Mutex for multithreading.
}

// Buffer creation function, occurs in O(n).
func New(size uint32) *cirbuf {
	if size == 0 {
		size = 4096 // Default value.
	}
	return &cirbuf{
		data:     make([]byte, size),
		readPtr:  0,
		writePtr: 0,
		size:     0,
		capacity: size,
	}
}

// Reading the buffer, occurs in O(1).
func (b *cirbuf) Read(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.size == 0 {
		return 0, ErrBufferEmpty
	}

	toRead := uint32(len(p))
	if toRead > b.size {
		toRead = b.size
	}

	firstPart := b.capacity - b.readPtr
	if firstPart > toRead {
		firstPart = toRead
	}

	copy(p, b.data[b.readPtr:b.readPtr+firstPart])

	if secondPart := toRead - firstPart; secondPart > 0 {
		copy(p[firstPart:], b.data[0:secondPart])
		b.readPtr = secondPart
	} else {
		b.readPtr += firstPart
	}

	if b.readPtr == b.capacity {
		b.readPtr = 0
	}

	return int(toRead), nil
}
