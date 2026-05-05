// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package buf

import (
	"errors"
	"math/bits"
	"sync"
)

// Implementation of a high-performance ring buffer for networking.

var (
	ErrBufferFull   = errors.New("buffer is full")
	ErrBufferEmpty  = errors.New("buffer is empty")
	ErrBufferClosed = errors.New("buffer is closed")
)

type cirbuf struct {
	data     []byte     // Data (slice bytes).
	readPtr  uint32     // The index from which the buffer reading begins.
	writePtr uint32     // The index at which writing to the buffer begins.
	size     uint32     // The current amount of data in the buffer.
	capacity uint32     // Total size of the array (always a power of 2).
	mask     uint32     // Mask for fast modulo operations (capacity - 1).
	mu       sync.Mutex // Mutex for multithreading.
}

// New creates a new buffer. Complexity: O(n) for memory allocation.
func New(size uint32) *cirbuf {
	if size == 0 {
		size = 4096 // Default value.
	}

	// Optimization: ensure capacity is a power of two for bitwise indexing.
	capacity := size
	if size&(size-1) != 0 {
		capacity = 1 << (32 - bits.LeadingZeros32(size-1))
	}

	return &cirbuf{
		data:     make([]byte, capacity),
		capacity: capacity,
		mask:     capacity - 1,
	}
}

// Write adds data to the buffer. Complexity: O(1) algorithmically.
// Returns ErrBufferFull if there is not enough space for the entire slice.
func (b *cirbuf) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.data == nil {
		return 0, ErrBufferClosed
	}

	free := b.capacity - b.size
	toWrite := uint32(len(p))

	if toWrite > free {
		return 0, ErrBufferFull
	}

	// Explicit slice bounds for safety and optimal compiler performance.
	if b.writePtr+toWrite <= b.capacity {
		copy(b.data[b.writePtr:b.writePtr+toWrite], p[:toWrite])
	} else {
		firstPart := b.capacity - b.writePtr
		copy(b.data[b.writePtr:b.capacity], p[:firstPart])
		copy(b.data[0:toWrite-firstPart], p[firstPart:toWrite])
	}

	b.writePtr = (b.writePtr + toWrite) & b.mask
	b.size += toWrite

	return int(toWrite), nil
}

// Read copies data from the buffer to p and removes it. Complexity: O(1).
func (b *cirbuf) Read(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.data == nil {
		return 0, ErrBufferClosed
	}
	if b.size == 0 {
		return 0, ErrBufferEmpty
	}

	toRead := uint32(len(p))
	if toRead > b.size {
		toRead = b.size
	}

	b.copyOut(p, toRead)

	b.readPtr = (b.readPtr + toRead) & b.mask
	b.size -= toRead

	return int(toRead), nil
}

// Peek reads data from the buffer without removing it. Complexity: O(1).
func (b *cirbuf) Peek(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.data == nil {
		return 0, ErrBufferClosed
	}
	if b.size == 0 {
		return 0, ErrBufferEmpty
	}

	toRead := uint32(len(p))
	if toRead > b.size {
		toRead = b.size
	}

	b.copyOut(p, toRead)
	return int(toRead), nil
}

// copyOut is an internal helper for wrap-around reads. Complexity: O(1).
func (b *cirbuf) copyOut(p []byte, toRead uint32) {
	if b.readPtr+toRead <= b.capacity {
		copy(p[:toRead], b.data[b.readPtr:b.readPtr+toRead])
	} else {
		firstPart := b.capacity - b.readPtr
		copy(p[:firstPart], b.data[b.readPtr:b.capacity])
		copy(p[firstPart:toRead], b.data[0:toRead-firstPart])
	}
}

// Len returns the current number of bytes available for reading. Complexity: O(1).
func (b *cirbuf) Len() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.size
}

// Available returns the number of bytes that can be written. Complexity: O(1).
func (b *cirbuf) Available() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capacity - b.size
}

// Cap returns the total capacity of the buffer. Complexity: O(1).
func (b *cirbuf) Cap() uint32 {
	return b.capacity // Immutable, no lock needed.
}

// Reset clears the buffer content without freeing memory. Complexity: O(1).
func (b *cirbuf) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.readPtr = 0
	b.writePtr = 0
	b.size = 0
}

// Skip discards n bytes from the buffer. Complexity: O(1).
func (b *cirbuf) Skip(n uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.data == nil {
		return ErrBufferClosed
	}
	if n > b.size {
		return ErrBufferEmpty
	}

	b.readPtr = (b.readPtr + n) & b.mask
	b.size -= n
	return nil
}

// Close destroys the buffer and releases memory. Complexity: O(1).
func (b *cirbuf) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = nil
	b.size = 0
	b.capacity = 0
}
