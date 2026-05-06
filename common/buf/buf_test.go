// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package buf

import (
	"bytes"
	"errors"
	"math"
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	cases := []struct {
		input    uint32
		expected uint32
	}{
		{0, 4096},
		{7, 8},
		{1024, 1024},
		{1 << 31, 1 << 31},
		{math.MaxUint32, 1 << 31},
	}
	for _, tc := range cases {
		b := New(tc.input)
		if b.Cap() != tc.expected {
			t.Errorf("New(%d): expected cap %d, got %d", tc.input, tc.expected, b.Cap())
		}
	}
}

func TestLifecycle(t *testing.T) {
	b := New(16)
	data := []byte("hello-go")

	b.Push(data)
	if b.Len() != 8 {
		t.Fatalf("Len: expected 8, got %d", b.Len())
	}

	peek := make([]byte, 5)
	b.Peek(peek)
	if !bytes.Equal(peek, []byte("hello")) || b.Len() != 8 {
		t.Error("Peek failed or modified buffer size")
	}

	if err := b.Skip(3); err != nil {
		t.Fatal(err)
	}
	if b.Len() != 5 {
		t.Error("Skip failed to advance read pointer")
	}

	res := make([]byte, 5)
	n, _ := b.Pop(res)
	if n != 5 || !bytes.Equal(res, []byte("lo-go")) {
		t.Errorf("Pop failed: got %s", string(res))
	}
}

func TestWrapAround(t *testing.T) {
	b := New(8)

	b.Push([]byte("12345"))
	b.Skip(4)

	b.Push([]byte("abcdef"))

	res := make([]byte, 7)
	n, _ := b.Pop(res)
	if n != 7 || string(res) != "5abcdef" {
		t.Errorf("WrapAround failed: expected '5abcdef', got '%s'", string(res))
	}
}

func TestErrors(t *testing.T) {
	b := New(4)

	_, err := b.Push([]byte("12345"))
	if !errors.Is(err, ErrBufferFull) {
		t.Error("Expected ErrBufferFull")
	}

	tmp := make([]byte, 1)
	_, err = b.Pop(tmp)
	if !errors.Is(err, ErrBufferEmpty) {
		t.Error("Expected ErrBufferEmpty")
	}

	if err := b.verifyInput(make([]byte, 0)); err != nil {
		t.Error("Valid input failed verification")
	}
}

func TestCloseBehavior(t *testing.T) {
	b := New(16)
	b.Push([]byte("payload"))
	b.Close()
	if !b.IsClosed() {
		t.Error("IsClosed should be true")
	}
	if _, err := b.Push([]byte("x")); !errors.Is(err, ErrBufferClosed) {
		t.Error("Push after close should fail")
	}
	if b.Available() != 0 {
		t.Error("Available should be 0 after close")
	}

	res := make([]byte, 7)
	n, err := b.Pop(res)
	if n != 7 || err != nil || string(res) != "payload" {
		t.Error("Pop should allow draining after Close")
	}

	_, err = b.Pop(res)
	if !errors.Is(err, ErrBufferClosed) {
		t.Error("Empty closed buffer should return ErrBufferClosed on Pop")
	}
}

func TestResets(t *testing.T) {
	b := New(8)
	b.Push([]byte("secret12"))

	b.Reset()
	if b.Len() != 0 || b.Available() != 8 {
		t.Error("Reset failed")
	}

	b.Push([]byte("password"))
	b.SecureReset()
	for _, v := range b.data {
		if v != 0 {
			t.Fatal("SecureReset failed to zero memory")
		}
	}
}

func TestConcurrency(t *testing.T) {
	b := New(1024)
	wg := sync.WaitGroup{}
	iters := 5000

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			for {
				if _, err := b.Push([]byte{1}); err == nil {
					break
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		count := 0
		for count < iters {
			tmp := make([]byte, 1)
			if n, _ := b.Pop(tmp); n > 0 {
				count++
			}
		}
	}()

	wg.Wait()
	if b.Len() != 0 {
		t.Errorf("Buffer should be empty, got %d", b.Len())
	}
}
