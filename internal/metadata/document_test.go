package metadata

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/segfaultd/lux/internal/protocol"
)

func TestDecodeStructuredMetadataAndRoundTrip(t *testing.T) {
	var metadata protocol.Encoder
	appendChunk(&metadata, KeyType, []byte{1, 0x0c, 0x41, 0, 0x12, 0x34})

	var elapsed protocol.Encoder
	elapsed.DQ(42)
	appendChunk(&metadata, KeyDecompilerElapsed, elapsed.Payload())
	appendChunk(&metadata, KeyFunctionComment, []byte("function note"))
	appendChunk(&metadata, KeyFunctionRepeatComment, []byte("repeatable note"))
	appendChunk(&metadata, KeyInstructionComments, offsetPayload(0x10, func(e *protocol.Encoder) {
		e.Bytes([]byte("instruction note"))
	}))
	appendChunk(&metadata, KeyInstructionRepeat, offsetPayload(0x20, func(e *protocol.Encoder) {
		e.Bytes([]byte("repeatable instruction"))
	}))
	appendChunk(&metadata, KeyExtraComments, offsetPayload(0x30, func(e *protocol.Encoder) {
		e.Bytes([]byte("anterior"))
		e.Bytes([]byte("posterior"))
	}))

	var stackPoints protocol.Encoder
	stackPoints.DD(0)
	stackPoints.DD(4)
	stackPoints.DQ(^uint64(15))
	stackPoints.DD(8)
	stackPoints.DQ(32)
	appendChunk(&metadata, KeyUserStackPoints, stackPoints.Payload())
	appendChunk(&metadata, KeyFrameDescription, []byte{0xde, 0xad})
	appendChunk(&metadata, KeyOperandRepresentation, []byte{0xbe, 0xef})
	appendChunk(&metadata, KeyExtendedOperands, []byte{0xca, 0xfe})
	appendChunk(&metadata, 99, []byte{0, 1, 2, 3})

	raw := append([]byte(nil), metadata.Payload()...)
	doc, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Size != len(raw) || len(doc.Chunks) != 12 {
		t.Fatalf("unexpected document: %#v", doc)
	}
	if doc.Summary.KnownChunks != 11 || doc.Summary.UnknownChunks != 1 ||
		doc.Summary.Comments != 6 || doc.Summary.StackPoints != 2 ||
		!doc.Summary.HasType || !doc.Summary.HasFrame || doc.Summary.OperandChunks != 2 {
		t.Fatalf("unexpected summary: %#v", doc.Summary)
	}

	typeChunk := doc.Chunks[0]
	if typeChunk.Key != "type" || typeChunk.Type == nil || !typeChunk.Type.UserDefined ||
		typeChunk.Type.Source != 1 || typeChunk.Type.Type != "0c41" ||
		typeChunk.Type.Fields != "1234" || !typeChunk.Editable {
		t.Fatalf("unexpected type chunk: %#v", typeChunk)
	}
	if got := *doc.Chunks[1].ElapsedSeconds; got != 42 {
		t.Fatalf("elapsed seconds = %d", got)
	}
	if got := *doc.Chunks[2].Text; got != "function note" {
		t.Fatalf("function comment = %q", got)
	}
	if comments := doc.Chunks[6].Comments; len(comments) != 2 ||
		comments[0].Type != "anterior" || comments[1].Type != "posterior" ||
		comments[0].Offset == nil || *comments[0].Offset != 0x30 {
		t.Fatalf("extra comments = %#v", comments)
	}
	if points := doc.Chunks[7].StackPoints; len(points) != 2 ||
		points[0] != (StackPoint{Offset: 4, Delta: -16}) ||
		points[1] != (StackPoint{Offset: 12, Delta: 32}) {
		t.Fatalf("stack points = %#v", points)
	}
	if doc.Chunks[8].Editable || doc.Chunks[11].Known ||
		doc.Chunks[11].Key != "unknown_99" || doc.Chunks[11].Payload != "00010203" {
		t.Fatalf("opaque chunks not represented correctly: %#v %#v", doc.Chunks[8], doc.Chunks[11])
	}

	roundTrip, err := Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip, raw) {
		t.Fatalf("round trip changed bytes:\n got %x\nwant %x", roundTrip, raw)
	}
}

func TestDecodeOffsetResetAndEmptyDocument(t *testing.T) {
	var payload protocol.Encoder
	payload.DD(100)
	payload.DD(2)
	payload.Bytes([]byte("first"))
	payload.DD(0)
	payload.DD(50)
	payload.DD(5)
	payload.Bytes([]byte("second"))

	var raw protocol.Encoder
	appendChunk(&raw, KeyInstructionComments, payload.Payload())
	doc, err := Decode(raw.Payload())
	if err != nil {
		t.Fatal(err)
	}
	comments := doc.Chunks[0].Comments
	if len(comments) != 2 || *comments[0].Offset != 102 || *comments[1].Offset != 55 {
		t.Fatalf("offset reset decoded incorrectly: %#v", comments)
	}

	empty, err := Decode(nil)
	if err != nil || empty.Size != 0 || empty.Chunks == nil || len(empty.Chunks) != 0 {
		t.Fatalf("empty decode = %#v, %v", empty, err)
	}
	encoded, err := Encode(empty)
	if err != nil || len(encoded) != 0 {
		t.Fatalf("empty encode = %x, %v", encoded, err)
	}
}

func TestDecodeChunkFailuresRemainLossless(t *testing.T) {
	tests := []struct {
		name    string
		code    uint32
		payload []byte
		error   string
	}{
		{"empty type", KeyType, nil, "type payload is empty"},
		{"bad elapsed", KeyDecompilerElapsed, []byte{1}, "unexpected end"},
		{"elapsed trailing", KeyDecompilerElapsed, []byte{0, 1, 2}, "trailing bytes"},
		{"bad function UTF-8", KeyFunctionComment, []byte{0xff}, "UTF-8"},
		{"bad instruction sequence", KeyInstructionComments, nil, "unexpected end"},
		{"bad instruction string", KeyInstructionComments, []byte{0, 1, 1, 0xff}, "UTF-8"},
		{"bad extra sequence", KeyExtraComments, []byte{0, 1, 1, 'a'}, "unexpected end"},
		{"bad stack points", KeyUserStackPoints, []byte{0, 1}, "unexpected end"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw protocol.Encoder
			appendChunk(&raw, tt.code, tt.payload)
			original := append([]byte(nil), raw.Payload()...)
			doc, err := Decode(original)
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Chunks) != 1 || !strings.Contains(doc.Chunks[0].Error, tt.error) ||
				doc.Summary.DecodeFailures != 1 {
				t.Fatalf("unexpected failure document: %#v", doc)
			}
			roundTrip, err := Encode(doc)
			if err != nil || !bytes.Equal(roundTrip, original) {
				t.Fatalf("lossless failure round trip = %x, %v", roundTrip, err)
			}
		})
	}
}

func TestDecodeContainerErrorsAndInspect(t *testing.T) {
	tests := [][]byte{
		{0xc0},
		{byte(KeyFunctionComment), 5, 'x'},
	}
	for _, raw := range tests {
		if _, err := Decode(raw); err == nil {
			t.Fatalf("Decode(%x) unexpectedly succeeded", raw)
		}
		doc := Inspect(raw)
		if doc.Error == "" {
			t.Fatalf("Inspect(%x) did not retain error", raw)
		}
	}
}

func TestEncodeRejectsInvalidPayloadHex(t *testing.T) {
	_, err := Encode(Document{Chunks: []Chunk{{Code: 3, Payload: "xyz"}}})
	if err == nil || !strings.Contains(err.Error(), "hexadecimal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeTypeVariantsAndSignedElapsed(t *testing.T) {
	tests := []struct {
		payload []byte
		source  uint8
		user    bool
		typ     string
		fields  string
	}{
		{[]byte{0}, 0, false, "", ""},
		{[]byte{2, 1, 2, 3}, 2, true, "010203", ""},
		{[]byte{0, 1, 0}, 0, false, "01", ""},
	}
	for _, tt := range tests {
		got, err := decodeType(tt.payload)
		if err != nil {
			t.Fatal(err)
		}
		if got.Source != tt.source || got.UserDefined != tt.user ||
			got.Type != tt.typ || got.Fields != tt.fields {
			t.Fatalf("decodeType(%x) = %#v", tt.payload, got)
		}
	}

	var encoded protocol.Encoder
	encoded.DQ(^uint64(0))
	got, err := decodeInt64(encoded.Payload())
	if err != nil || got != -1 {
		t.Fatalf("signed elapsed = %d, %v (%s)", got, err, hex.EncodeToString(encoded.Payload()))
	}
}
