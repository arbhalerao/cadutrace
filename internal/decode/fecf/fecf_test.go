package fecf

import "testing"

func TestSumCheckValue(t *testing.T) {
	if got := Sum([]byte("123456789")); got != 0x29B1 {
		t.Fatalf("Sum = %#04x, want 0x29b1", got)
	}
}

func TestValid(t *testing.T) {
	f := append([]byte("frame body"), 0, 0)
	c := Sum(f[:len(f)-2])
	f[len(f)-2], f[len(f)-1] = byte(c>>8), byte(c)
	if !Valid(f) {
		t.Fatal("valid frame rejected")
	}
	f[3] ^= 0x10
	if Valid(f) {
		t.Fatal("corrupted frame accepted")
	}
}
