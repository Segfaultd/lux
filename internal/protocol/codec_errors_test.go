package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestEncoderDecoderCollections(t *testing.T) {
	var e Encoder
	e.U32s([]uint32{1, 0x80, 0xffffffff})
	e.Strings([]string{"one", "two"})
	d := NewDecoder(e.Payload())
	numbers, err := d.U32s(10)
	if err != nil {
		t.Fatal(err)
	}
	stringsValue, err := d.Strings(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(numbers) != 3 || numbers[2] != 0xffffffff ||
		len(stringsValue) != 2 || stringsValue[1] != "two" || d.Remaining() != 0 {
		t.Fatalf("round trip failed: %v %v", numbers, stringsValue)
	}
}

func TestDecoderErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		call func(*Decoder) error
	}{
		{"byte eof", nil, func(d *Decoder) error { _, err := d.Byte(); return err }},
		{"dd two byte truncated", []byte{0x80}, func(d *Decoder) error { _, err := d.DD(); return err }},
		{"dd four byte truncated", []byte{0xc0, 1}, func(d *Decoder) error { _, err := d.DD(); return err }},
		{"dd five byte truncated", []byte{0xff, 1}, func(d *Decoder) error { _, err := d.DD(); return err }},
		{"dq truncated", []byte{1}, func(d *Decoder) error { _, err := d.DQ(); return err }},
		{"cstring eof", nil, func(d *Decoder) error { _, err := d.CString(); return err }},
		{"cstring terminator missing", []byte("text"), func(d *Decoder) error { _, err := d.CString(); return err }},
		{"cstring invalid utf8", []byte{0xff, 0}, func(d *Decoder) error { _, err := d.CString(); return err }},
		{"bytes truncated", []byte{3, 1}, func(d *Decoder) error { _, err := d.Bytes(); return err }},
		{"fixed negative", nil, func(d *Decoder) error { _, err := d.Fixed(-1); return err }},
		{"fixed truncated", []byte{1}, func(d *Decoder) error { _, err := d.Fixed(2); return err }},
		{"count exceeds max", []byte{2}, func(d *Decoder) error { _, err := d.Count(1); return err }},
		{"u32 values truncated", []byte{1}, func(d *Decoder) error { _, err := d.U32s(2); return err }},
		{"string values truncated", []byte{1}, func(d *Decoder) error { _, err := d.Strings(2); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(NewDecoder(test.data)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestReadPacketErrorsAndLimits(t *testing.T) {
	t.Run("truncated header", func(t *testing.T) {
		if _, err := ReadPacket(strings.NewReader("abc")); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("HTTP case insensitive", func(t *testing.T) {
		if _, err := ReadPacket(strings.NewReader("get /")); !errors.Is(err, ErrHTTP) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("oversized generic", func(t *testing.T) {
		var header [5]byte
		binary.BigEndian.PutUint32(header[:4], 50*1024+1)
		header[4] = CodeHello
		if _, err := ReadPacket(bytes.NewReader(header[:])); !errors.Is(err, ErrPacketTooBig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("oversized pull", func(t *testing.T) {
		var header [5]byte
		binary.BigEndian.PutUint32(header[:4], 50*1024*1024+1)
		header[4] = CodePullMetadata
		if _, err := ReadPacket(bytes.NewReader(header[:])); !errors.Is(err, ErrPacketTooBig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("oversized push", func(t *testing.T) {
		var header [5]byte
		binary.BigEndian.PutUint32(header[:4], 200*1024*1024+1)
		header[4] = CodePushMetadata
		if _, err := ReadPacket(bytes.NewReader(header[:])); !errors.Is(err, ErrPacketTooBig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("truncated payload", func(t *testing.T) {
		var wire bytes.Buffer
		var header [5]byte
		binary.BigEndian.PutUint32(header[:4], 2)
		header[4] = CodeHello
		wire.Write(header[:])
		wire.WriteByte(1)
		if _, err := ReadPacket(&wire); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestWritePacketShortAndFailingWriters(t *testing.T) {
	if err := WritePacket(zeroWriter{}, CodeOK, nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero writer: %v", err)
	}
	want := errors.New("write failed")
	if err := WritePacket(errorWriter{err: want}, CodeOK, nil); !errors.Is(err, want) {
		t.Fatalf("error writer: %v", err)
	}
	var partial partialWriter
	if err := WritePacket(&partial, CodeOK, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	packet, err := ReadPacket(bytes.NewReader(partial.data))
	if err != nil || packet.Code != CodeOK || !bytes.Equal(packet.Payload, []byte{1, 2, 3}) {
		t.Fatalf("partial writer packet %#v, error %v", packet, err)
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type partialWriter struct{ data []byte }

func (w *partialWriter) Write(value []byte) (int, error) {
	n := min(2, len(value))
	w.data = append(w.data, value[:n]...)
	return n, nil
}
