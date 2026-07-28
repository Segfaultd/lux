package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDDRoundTrip(t *testing.T) {
	values := []uint32{0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1fffff, 0x200000, 0xffffffff}
	for _, want := range values {
		var e Encoder
		e.DD(want)
		d := NewDecoder(e.Payload())
		got, err := d.DD()
		if err != nil {
			t.Fatalf("decode %#x: %v", want, err)
		}
		if got != want {
			t.Errorf("round trip %#x: got %#x", want, got)
		}
		if d.Remaining() != 0 {
			t.Errorf("round trip %#x left %d bytes", want, d.Remaining())
		}
	}
}

func TestLumenSerializationGolden(t *testing.T) {
	var e Encoder
	e.Fixed([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	e.CString("somestring")
	e.Bytes([]byte("bytes"))
	e.DD(0x20)
	e.DQ(0x20)
	want := []byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10somestring\x00\x05bytes\x20\x00\x20")
	if !bytes.Equal(e.Payload(), want) {
		t.Fatalf("golden bytes mismatch:\n got %x\nwant %x", e.Payload(), want)
	}
}

func TestPacketFraming(t *testing.T) {
	var wire bytes.Buffer
	payload := []byte{1, 2, 3, 4}
	if err := WritePacket(&wire, CodePullMetadata, payload); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(wire.Bytes()[:4]); got != uint32(len(payload)) {
		t.Fatalf("payload length: got %d", got)
	}
	packet, err := ReadPacket(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Code != CodePullMetadata || !bytes.Equal(packet.Payload, payload) {
		t.Fatalf("bad packet: %#v", packet)
	}
}

func TestDecodeHelloWithCredentials(t *testing.T) {
	var e Encoder
	e.DD(5)
	e.Bytes([]byte{0xaa, 0xbb})
	e.Fixed([]byte{1, 2, 3, 4, 5, 6})
	e.DD(7)
	e.CString("guest")
	e.CString("secret")
	hello, err := DecodeHello(e.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if hello.ProtocolVersion != 5 || hello.Unknown != 7 {
		t.Fatalf("unexpected hello: %#v", hello)
	}
	if hello.Credentials == nil || hello.Credentials.Username != "guest" || hello.Credentials.Password != "secret" {
		t.Fatalf("unexpected credentials: %#v", hello.Credentials)
	}
}
