package randomizer

const period = 255 // byte-aligned sequence period (the bit sequence is 255 bits)

var seq = buildSequence()

// buildSequence builds one period from h(x) = x^8 + x^7 + x^5 + x^3 + 1, register
// preset to all ones: a[n] = a[n-1] ^ a[n-3] ^ a[n-5] ^ a[n-8], packed MSB-first
func buildSequence() [period]byte {
	const nbits = period * 8
	var a [nbits]byte
	for i := range 8 {
		a[i] = 1
	}
	for n := 8; n < nbits; n++ {
		a[n] = a[n-1] ^ a[n-3] ^ a[n-5] ^ a[n-8]
	}
	var s [period]byte
	for i := range s {
		var b byte
		for j := range 8 {
			b = b<<1 | a[i*8+j]
		}
		s[i] = b
	}
	return s
}

// Apply XORs b in place with the sequence from the frame boundary
// It's an involution, so the same call randomizes and derandomizes
func Apply(b []byte) {
	j := 0
	for i := range b {
		b[i] ^= seq[j]
		if j++; j == period {
			j = 0
		}
	}
}

// Sequence returns a copy of one full period, for tooling
func Sequence() []byte {
	out := make([]byte, period)
	copy(out, seq[:])
	return out
}
