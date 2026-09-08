package ascon

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type Context struct {
	state [40]byte // 320 bytes of state
	key   [16]byte
	nonce [16]byte
}

func NewContext(key [16]byte, nonce [16]byte) *Context {
	return &Context{
		state: [40]byte{
			0x80, 0x80, 0x0c, 0x08, 0x00, 0x00, 0x00, 0x00, // S0 [ 0: 7]
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], // S1 [ 8:15]
			key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15], // S2 [16:23]
			nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7], // S3 [24:31]
			nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14], nonce[15], // S4 [32:39]
		},
		key:   key,
		nonce: nonce,
	}
}

func (c *Context) Dump(tag string) {
	fmt.Printf("%s:\n  %s", tag, hex.Dump(c.state[:]))
}

func (c *Context) DumpState(tag string) {
	fmt.Printf("%s:\n  %016x %016x %016x %016x %016x\n", tag, c.word(0), c.word(1), c.word(2), c.word(3), c.word(4))
}

func (c *Context) load() {
	c.setWord(0, 0x80800c0800000000)
	c.setWord(1, binary.BigEndian.Uint64(c.key[0:8]))
	c.setWord(2, binary.BigEndian.Uint64(c.key[8:16]))
	c.setWord(3, binary.BigEndian.Uint64(c.nonce[0:8]))
	c.setWord(4, binary.BigEndian.Uint64(c.nonce[8:16]))
}

func (c *Context) initialize() {
	c.load()
	c.permutate(12)

	for i, v := range c.key {
		c.state[24+i] ^= v
	}
}

func (c *Context) processAssociated(associated []byte) {
	if len(associated) > 0 {
		chunks := parse(pad(associated))
		for _, chunk := range chunks {
			for j := range 16 {
				c.state[j] ^= chunk[j]
			}
			c.permutate(8)
		}
	}

	c.state[39] ^= 0x01
}

func pad(plaintext []byte) []byte {
	zeroes := 16 - len(plaintext)%16 - 1
	padded := append(plaintext, 0x80)
	for range zeroes {
		padded = append(padded, 0)
	}
	return padded
}
func (c *Context) processPlaintext(plaintext []byte) []byte {
	length := len(plaintext)
	chunks := parse(pad(plaintext))
	var ciphertext []byte
	for _, chunk := range chunks[:len(chunks)-1] {
		for j := range 16 {
			v := c.state[0+j] ^ chunk[j]
			c.state[0+j] = v
			if length > 0 {
				length--
				ciphertext = append(ciphertext, v)
			}
		}
		c.permutate(8)
	}

	// last chunk
	last := chunks[len(chunks)-1]
	for i := range 16 {
		v := c.state[i] ^ last[i]
		c.state[i] = v
		if length > 0 {
			length--
			ciphertext = append(ciphertext, v)
		}

	}

	return ciphertext
}

func (c *Context) finalize() []byte {
	var tag []byte

	for i := range 16 {
		c.state[16+i] ^= c.key[i]
	}

	c.permutate(12)
	for i := range 16 {
		v := c.state[24+i] ^ c.key[i]
		c.state[24+i] = v
		tag = append(tag, v)
	}
	return tag
}

func parse(data []byte) [][16]byte {
	if len(data) == 0 {
		return nil
	}

	// Calculate total chunks needed (rounding up)
	numChunks := (len(data) + 15) / 16
	chunks := make([][16]byte, numChunks)

	for i := range numChunks {
		start := i * 16
		end := start + 16

		if end > len(data) {
			// Copy remaining bytes into zero-initialized array
			copy(chunks[i][:], data[start:])
		} else {
			copy(chunks[i][:], data[start:end])
		}
	}

	return chunks
}

func (c *Context) Encrypt(plaintext []byte, associated []byte) []byte {
	c.initialize()
	c.processAssociated(associated)
	ciphertext := c.processPlaintext(plaintext)
	tag := c.finalize()

	return append(ciphertext, tag...)
}

func (c *Context) substitute(words [5]uint64) [5]uint64 {
	x0, x1, x2, x3, x4 := words[0], words[1], words[2], words[3], words[4]

	x0 ^= x4
	x4 ^= x3
	x2 ^= x1

	t0, t1, t2, t3, t4 := x0, x1, x2, x3, x4

	t0 = ^t0
	t1 = ^t1
	t2 = ^t2
	t3 = ^t3
	t4 = ^t4

	t0 &= x1
	t1 &= x2
	t2 &= x3
	t3 &= x4
	t4 &= x0

	x0 ^= t1
	x1 ^= t2
	x2 ^= t3
	x3 ^= t4
	x4 ^= t0

	x1 ^= x0
	x0 ^= x4
	x3 ^= x2
	x2 = ^x2

	return [5]uint64{x0, x1, x2, x3, x4}
}

func rotateRight(val uint64, shift uint) uint64 {
	shift %= 64
	return (val >> shift) | (val << (64 - shift))
}

func (c *Context) permutate(count int) {
	constants := [16]uint8{0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}
	for i := range count {
		// constant addition
		{
			constant := constants[16-count+i]
			c.state[23] = c.state[23] ^ constant
		}

		// substitution
		{
			c.setWords(c.substitute(c.words()))
		}

		// diffusion
		{
			s0, s1, s2, s3, s4 := c.word(0), c.word(1), c.word(2), c.word(3), c.word(4)
			c.setWord(0, s0^rotateRight(s0, 19)^rotateRight(s0, 28))
			c.setWord(1, s1^rotateRight(s1, 61)^rotateRight(s1, 39))
			c.setWord(2, s2^rotateRight(s2, 1)^rotateRight(s2, 6))
			c.setWord(3, s3^rotateRight(s3, 10)^rotateRight(s3, 17))
			c.setWord(4, s4^rotateRight(s4, 7)^rotateRight(s4, 41))
		}
	}
}

func (c *Context) word(i int) uint64 {
	start := i * 8
	stop := (i + 1) * 8
	return binary.BigEndian.Uint64(c.state[start:stop])
}

func (c *Context) setWord(i int, v uint64) {
	start := i * 8
	stop := (i + 1) * 8
	binary.BigEndian.PutUint64(c.state[start:stop], v)
}

func (c *Context) words() [5]uint64 {
	var result [5]uint64
	for i := range 5 {
		result[i] = c.word(i)
	}
	return result
}

func (c *Context) setWords(values [5]uint64) {
	for i := range 5 {
		c.setWord(i, values[i])
	}
}
