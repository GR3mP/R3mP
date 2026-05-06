// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package buf

import (
	"errors"
	"math"
	"sync"
)

var (
	ErrBufferFull    = errors.New("buffer is full")
	ErrBufferEmpty   = errors.New("buffer is empty")
	ErrBufferClosed  = errors.New("buffer is closed")
	ErrTooLarge      = errors.New("input slice exceeds maximum uint32 capacity")
	ErrNotEnoughData = errors.New("not enough data in buffer")
)

const maxCapacity uint32 = 1 << 31

type cirbuf struct {
	data     []byte
	readPtr  uint32
	writePtr uint32
	size     uint32
	capacity uint32
	mask     uint32
	isClosed bool
	mu       sync.RWMutex
}

// New creates a ring buffer with capacity rounded up to the nearest power of 2.
// Default size is 4096 if 0 is provided. Max size is 2^31.
func New(size uint32) *cirbuf {
	if size == 0 {
		size = 4096
	}
	if size > maxCapacity {
		size = maxCapacity
	}

	var capacity uint32 = 1
	for capacity < size {
		if capacity >= maxCapacity {
			capacity = maxCapacity
			break
		}
		capacity <<= 1
	}

	return &cirbuf{
		data:     make([]byte, capacity),
		capacity: capacity,
		mask:     capacity - 1,
	}
}

// Push adds all bytes from p to the buffer.
// It is an all-or-nothing operation. Returns ErrBufferClosed if buffer is closed.
func (b *cirbuf) Push(p []byte) (n int, err error) {
	if err := b.verifyInput(p); err != nil {
		return 0, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.isClosed {
		return 0, ErrBufferClosed
	}

	toWrite := uint32(len(p))
	if toWrite > (b.capacity - b.size) {
		return 0, ErrBufferFull
	}

	firstPart := b.capacity - b.writePtr
	if toWrite < firstPart {
		firstPart = toWrite
	}

	copy(b.data[b.writePtr:], p[:firstPart])
	if toWrite > firstPart {
		copy(b.data[:toWrite-firstPart], p[firstPart:])
	}

	b.writePtr = (b.writePtr + toWrite) & b.mask
	b.size += toWrite

	return len(p), nil
}

// Pop copies up to len(p) bytes from the buffer and removes them.
// Successive calls to Pop are allowed after Close() until the buffer is empty (draining).
func (b *cirbuf) Pop(p []byte) (n int, err error) {
	if err := b.verifyInput(p); err != nil {
		return 0, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.size == 0 {
		if b.isClosed {
			return 0, ErrBufferClosed
		}
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

// Peek returns a snapshot of the data without removing it.
func (b *cirbuf) Peek(p []byte) (n int, err error) {
	if err := b.verifyInput(p); err != nil {
		return 0, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.size == 0 {
		if b.isClosed {
			return 0, ErrBufferClosed
		}
		return 0, ErrBufferEmpty
	}

	toRead := uint32(len(p))
	if toRead > b.size {
		toRead = b.size
	}

	b.copyOut(p, toRead)
	return int(toRead), nil
}

// copyOut internal helper. Caller must hold RLock/Lock and verify len(p) >= toRead.
func (b *cirbuf) copyOut(p []byte, toRead uint32) {
	if uint32(len(p)) < toRead {
		panic("buf: internal error: copyOut into insufficient slice")
	}
	firstPart := b.capacity - b.readPtr
	if toRead < firstPart {
		firstPart = toRead
	}

	copy(p, b.data[b.readPtr:b.readPtr+firstPart])
	if toRead > firstPart {
		copy(p[firstPart:toRead], b.data[:toRead-firstPart])
	}
}

// Skip advances the read pointer by n bytes.
// Skip is allowed after Close() to support draining semantics.
func (b *cirbuf) Skip(n uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if n > b.size {
		return ErrNotEnoughData
	}

	b.readPtr = (b.readPtr + n) & b.mask
	b.size -= n
	return nil
}

// IsClosed returns true if the buffer has been closed for writing.
func (b *cirbuf) IsClosed() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.isClosed
}

// Len returns the current number of bytes in the buffer.
func (b *cirbuf) Len() uint32 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.size
}

// Available returns the amount of free space. Returns 0 if closed.
func (b *cirbuf) Available() uint32 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.isClosed {
		return 0
	}
	return b.capacity - b.size
}

// Cap returns the total capacity of the buffer.
func (b *cirbuf) Cap() uint32 {
	return b.capacity
}

// Reset clears the buffer pointers. Does not zero the memory.
func (b *cirbuf) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.readPtr = 0
	b.writePtr = 0
	b.size = 0
}

// SecureReset clears pointers AND zeros the underlying memory.
func (b *cirbuf) SecureReset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.readPtr = 0
	b.writePtr = 0
	b.size = 0
	if b.data != nil {
		for i := range b.data {
			b.data[i] = 0
		}
	}
}

// Close marks the buffer as closed. Future Push calls will fail.
func (b *cirbuf) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.isClosed = true
}

func (b *cirbuf) verifyInput(p []byte) error {
	if uint64(len(p)) > math.MaxUint32 {
		return ErrTooLarge
	}
	return nil
}
