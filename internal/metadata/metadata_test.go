package metadata

import (
	"strings"
	"testing"

	"github.com/segfaultd/lux/internal/protocol"
)

func TestParseAllCommentKinds(t *testing.T) {
	var encoded protocol.Encoder
	appendChunk(&encoded, 1, []byte("ignored type"))
	appendChunk(&encoded, 2, []byte("ignored"))
	appendChunk(&encoded, 3, []byte("function comment"))
	appendChunk(&encoded, 4, []byte("repeatable function"))
	appendChunk(&encoded, 5, offsetPayload(0x10, func(e *protocol.Encoder) {
		e.Bytes([]byte("byte comment"))
	}))
	appendChunk(&encoded, 6, offsetPayload(0x20, func(e *protocol.Encoder) {
		e.Bytes([]byte("repeatable byte"))
	}))
	appendChunk(&encoded, 7, offsetPayload(0x30, func(e *protocol.Encoder) {
		e.Bytes([]byte("before"))
		e.Bytes([]byte("after"))
	}))
	appendChunk(&encoded, 9, []byte("ignored"))
	appendChunk(&encoded, 99, []byte("unknown ignored"))
	appendChunk(&encoded, 3, nil)

	comments, err := Parse(encoded.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if len(comments) != 6 {
		t.Fatalf("got %d comments: %#v", len(comments), comments)
	}
	if comments[0].Type != "function" || comments[0].Repeatable {
		t.Fatalf("function comment: %#v", comments[0])
	}
	if !comments[1].Repeatable {
		t.Fatalf("repeatable function comment: %#v", comments[1])
	}
	if comments[2].Offset == nil || *comments[2].Offset != 0x10 || comments[2].Type != "byte" {
		t.Fatalf("byte comment: %#v", comments[2])
	}
	if comments[3].Offset == nil || *comments[3].Offset != 0x20 || !comments[3].Repeatable {
		t.Fatalf("repeatable byte comment: %#v", comments[3])
	}
	if comments[4].Type != "anterior" || comments[5].Type != "posterior" {
		t.Fatalf("extra comments: %#v", comments[4:])
	}
}

func TestParseOffsetReset(t *testing.T) {
	var payload protocol.Encoder
	payload.DD(100)
	payload.DD(2)
	payload.Bytes([]byte("first"))
	payload.DD(0)
	payload.DD(50)
	payload.DD(5)
	payload.Bytes([]byte("second"))

	var encoded protocol.Encoder
	appendChunk(&encoded, 5, payload.Payload())
	comments, err := Parse(encoded.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if len(comments) != 2 || *comments[0].Offset != 102 || *comments[1].Offset != 55 {
		t.Fatalf("offset reset decoded incorrectly: %#v", comments)
	}
}

func TestScoreFiltersBoilerplate(t *testing.T) {
	usefulComments := []struct {
		code uint32
		text string
	}{
		{3, "human function note"},
		{5, "human byte note"},
		{7, "human anterior note"},
	}
	var usefulEncoded protocol.Encoder
	for _, item := range usefulComments {
		switch item.code {
		case 3:
			appendChunk(&usefulEncoded, item.code, []byte(item.text))
		case 5:
			appendChunk(&usefulEncoded, item.code, offsetPayload(0, func(e *protocol.Encoder) {
				e.Bytes([]byte(item.text))
			}))
		case 7:
			appendChunk(&usefulEncoded, item.code, offsetPayload(0, func(e *protocol.Encoder) {
				e.Bytes([]byte(item.text))
				e.Bytes(nil)
			}))
		}
	}
	if got := Score(usefulEncoded.Payload()); got != 30 {
		t.Fatalf("useful score %d, want 30", got)
	}

	boilerplate := []struct {
		kind string
		text string
	}{
		{"function", ""},
		{"function", "Microsoft VisualC v14 64bit runtime"},
		{"function", "Microsoft VisualC 64bit universal runtime"},
		{"byte", "Trap to Debugger"},
		{"byte", "jumptable 12 case"},
		{"byte", "switch jump"},
		{"byte", "switch 3 cases "},
		{"byte", "jump table for switch statement"},
		{"byte", "indirect table for switch statement"},
		{"byte", "Microsoft VisualC v7/14 64bit runtime"},
		{"byte", "Microsoft VisualC v7/14 64bit runtime\nMicrosoft VisualC v14 64bit runtime"},
		{"byte", "Microsoft VisualC v14 64bit runtime"},
		{"anterior", "; Exported entry symbol"},
		{"posterior", ""},
	}
	for _, item := range boilerplate {
		if useful(Comment{Type: item.kind, Text: item.text}) {
			t.Errorf("boilerplate considered useful: %#v", item)
		}
	}
	if !useful(Comment{Type: "posterior", Text: "after"}) {
		t.Fatal("useful posterior comment rejected")
	}
}

func TestParseErrorsAndBestEffort(t *testing.T) {
	if _, err := Parse([]byte{3, 5, 1}); err == nil {
		t.Fatal("expected truncated chunk error")
	}
	if Score([]byte{3, 5, 1}) != 0 {
		t.Fatal("invalid metadata should score zero")
	}
	comments := ParseBestEffort([]byte{3, 5, 1})
	if len(comments) != 1 || comments[0].Type != "parse-error" ||
		!strings.Contains(comments[0].Text, "could not be decoded") {
		t.Fatalf("unexpected best-effort result: %#v", comments)
	}
	if got := ParseBestEffort(nil); got != nil {
		t.Fatalf("empty metadata should return nil, got %#v", got)
	}
}

func appendChunk(e *protocol.Encoder, code uint32, data []byte) {
	e.DD(code)
	e.Bytes(data)
}

func offsetPayload(base uint32, value func(*protocol.Encoder)) []byte {
	var e protocol.Encoder
	e.DD(base)
	e.DD(0)
	value(&e)
	return append([]byte(nil), e.Payload()...)
}
