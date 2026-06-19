package bufpool

import "sync"

// PacketBufCap holds the largest possible space packet, so reassembly never grows a buffer
const PacketBufCap = 6 + 0xFFFF + 1 // 65542, matches ccsdsdefs.MaxSpacePacket

var pool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, PacketBufCap)
		return &b
	},
}

// GetPtr returns a pooled buffer reset to zero length
// Pointers (not []byte) avoid per-Put slice-header boxing
func GetPtr() *[]byte {
	p := pool.Get().(*[]byte)
	*p = (*p)[:0]
	return p
}

// PutPtr returns a buffer to the pool, dropping any grown past PacketBufCap
func PutPtr(p *[]byte) {
	if p == nil || cap(*p) < PacketBufCap {
		return
	}
	pool.Put(p)
}
