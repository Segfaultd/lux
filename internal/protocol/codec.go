package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

var (
	ErrUnexpectedEOF = errors.New("unexpected end of Lumina payload")
	ErrInvalidData   = errors.New("invalid Lumina payload")
	ErrHTTP          = errors.New("HTTP request received on Lumina port")
	ErrPacketTooBig  = errors.New("Lumina packet exceeds size limit")
)

// Encoder implements the compact, positional serialization used by Lumina.
type Encoder struct {
	buf bytes.Buffer
}

func (e *Encoder) Byte(v byte) { _ = e.buf.WriteByte(v) }

func (e *Encoder) DD(v uint32) {
	switch {
	case v <= 0x7f:
		e.Byte(byte(v))
	case v <= 0x3fff:
		e.Byte(0x80 | byte(v>>8))
		e.Byte(byte(v))
	case v <= 0x1fffff:
		e.Byte(0xc0)
		e.Byte(byte(v >> 16))
		e.Byte(byte(v >> 8))
		e.Byte(byte(v))
	default:
		e.Byte(0xff)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		_, _ = e.buf.Write(b[:])
	}
}

func (e *Encoder) DQ(v uint64) {
	e.DD(uint32(v >> 32))
	e.DD(uint32(v))
}

func (e *Encoder) CString(v string) {
	_, _ = e.buf.WriteString(v)
	e.Byte(0)
}

func (e *Encoder) Bytes(v []byte) {
	e.DD(uint32(len(v)))
	_, _ = e.buf.Write(v)
}

func (e *Encoder) Fixed(v []byte) { _, _ = e.buf.Write(v) }

func (e *Encoder) U32s(v []uint32) {
	e.DD(uint32(len(v)))
	for _, n := range v {
		e.DD(n)
	}
}

func (e *Encoder) Strings(v []string) {
	e.DD(uint32(len(v)))
	for _, s := range v {
		e.CString(s)
	}
}

func (e *Encoder) Payload() []byte { return e.buf.Bytes() }

// Decoder reads the same compact, positional encoding.
type Decoder struct {
	data []byte
	pos  int
}

func NewDecoder(data []byte) *Decoder { return &Decoder{data: data} }

func (d *Decoder) Remaining() int { return len(d.data) - d.pos }

func (d *Decoder) Byte() (byte, error) {
	if d.Remaining() < 1 {
		return 0, ErrUnexpectedEOF
	}
	v := d.data[d.pos]
	d.pos++
	return v, nil
}

func (d *Decoder) DD() (uint32, error) {
	first, err := d.Byte()
	if err != nil {
		return 0, err
	}
	switch {
	case first&0x80 == 0:
		return uint32(first), nil
	case first&0x40 == 0:
		second, err := d.Byte()
		if err != nil {
			return 0, err
		}
		return uint32(first&0x3f)<<8 | uint32(second), nil
	case first&0x20 == 0:
		if d.Remaining() < 3 {
			return 0, ErrUnexpectedEOF
		}
		v := uint32(first&0x1f)<<24 |
			uint32(d.data[d.pos])<<16 |
			uint32(d.data[d.pos+1])<<8 |
			uint32(d.data[d.pos+2])
		d.pos += 3
		return v, nil
	default:
		if d.Remaining() < 4 {
			return 0, ErrUnexpectedEOF
		}
		v := binary.BigEndian.Uint32(d.data[d.pos : d.pos+4])
		d.pos += 4
		return v, nil
	}
}

func (d *Decoder) DQ() (uint64, error) {
	hi, err := d.DD()
	if err != nil {
		return 0, err
	}
	lo, err := d.DD()
	if err != nil {
		return 0, err
	}
	return uint64(hi)<<32 | uint64(lo), nil
}

func (d *Decoder) CString() (string, error) {
	if d.Remaining() <= 0 {
		return "", ErrUnexpectedEOF
	}
	i := bytes.IndexByte(d.data[d.pos:], 0)
	if i < 0 {
		return "", ErrUnexpectedEOF
	}
	s := string(d.data[d.pos : d.pos+i])
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%w: string is not valid UTF-8", ErrInvalidData)
	}
	d.pos += i + 1
	return s, nil
}

func (d *Decoder) Bytes() ([]byte, error) {
	n, err := d.DD()
	if err != nil {
		return nil, err
	}
	return d.Fixed(int(n))
}

func (d *Decoder) Fixed(n int) ([]byte, error) {
	if n < 0 || d.Remaining() < n {
		return nil, ErrUnexpectedEOF
	}
	v := d.data[d.pos : d.pos+n]
	d.pos += n
	return v, nil
}

func (d *Decoder) Count(max uint32) (uint32, error) {
	n, err := d.DD()
	if err != nil {
		return 0, err
	}
	if n > max {
		return 0, fmt.Errorf("%w: sequence count %d exceeds %d", ErrInvalidData, n, max)
	}
	return n, nil
}

func (d *Decoder) U32s(max uint32) ([]uint32, error) {
	n, err := d.Count(max)
	if err != nil {
		return nil, err
	}
	out := make([]uint32, n)
	for i := range out {
		out[i], err = d.DD()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (d *Decoder) Strings(max uint32) ([]string, error) {
	n, err := d.Count(max)
	if err != nil {
		return nil, err
	}
	out := make([]string, n)
	for i := range out {
		out[i], err = d.CString()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

type Packet struct {
	Code    byte
	Payload []byte
}

func maxPacketSize(code byte) uint32 {
	switch code {
	case CodePullMetadata:
		return 50 * 1024 * 1024
	case CodePushMetadata:
		return 200 * 1024 * 1024
	default:
		return 50 * 1024
	}
}

func ReadPacket(r io.Reader) (Packet, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Packet{}, err
	}
	for _, verb := range [...]string{"GET /", "POST ", "HEAD ", "DELET", "PATCH", "PUT /", "OPTIO"} {
		if strings.EqualFold(string(header[:]), verb) {
			return Packet{}, ErrHTTP
		}
	}
	n := binary.BigEndian.Uint32(header[:4])
	code := header[4]
	if n > maxPacketSize(code) {
		return Packet{}, fmt.Errorf("%w: code=%#x size=%d", ErrPacketTooBig, code, n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Packet{}, err
	}
	return Packet{Code: code, Payload: payload}, nil
}

func WritePacket(w io.Writer, code byte, payload []byte) error {
	var header [5]byte
	binary.BigEndian.PutUint32(header[:4], uint32(len(payload)))
	header[4] = code
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
