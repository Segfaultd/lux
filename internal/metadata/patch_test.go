package metadata

import (
	"bytes"
	"strings"
	"testing"

	"github.com/segfaultd/lux/internal/protocol"
)

func intPointer(value int) *int          { return &value }
func uint32Pointer(value uint32) *uint32 { return &value }
func stringPointer(value string) *string { return &value }
func int64Pointer(value int64) *int64    { return &value }

func TestApplyPatchStructuredFieldsPreservesOpaqueChunks(t *testing.T) {
	offsetA, offsetB := uint32(10), uint32(4)
	var raw protocol.Encoder
	appendChunk(&raw, KeyFunctionComment, []byte("before"))
	appendChunk(&raw, 77, []byte{0xde, 0xad, 0xbe, 0xef})
	appendChunk(&raw, KeyInstructionComments, offsetPayload(offsetA, func(out *protocol.Encoder) {
		out.Bytes([]byte("old instruction"))
	}))
	appendChunk(&raw, KeyUserStackPoints, encodeStackPoints([]StackPoint{{Offset: 1, Delta: -8}}))

	comments := []Comment{
		{Offset: &offsetA, Type: "instruction", Text: "later"},
		{Offset: &offsetA, Type: "instruction", Text: "same offset"},
		{Offset: &offsetB, Type: "instruction", Text: "backwards"},
	}
	points := []StackPoint{{Offset: 8, Delta: -16}, {Offset: 16, Delta: 24}}
	patched, err := ApplyPatch(raw.Payload(), PatchRequest{Mutations: []Mutation{
		{Operation: "set", Index: intPointer(0), Text: stringPointer("after")},
		{Operation: "set", Index: intPointer(2), Comments: &comments},
		{Operation: "set", Index: intPointer(3), StackPoints: &points},
		{Operation: "append", Code: uint32Pointer(KeyDecompilerElapsed), ElapsedSeconds: int64Pointer(123)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Decode(patched)
	if err != nil {
		t.Fatal(err)
	}
	if got := *doc.Chunks[0].Text; got != "after" {
		t.Fatalf("text = %q", got)
	}
	if doc.Chunks[1].Code != 77 || doc.Chunks[1].Payload != "deadbeef" {
		t.Fatalf("unknown chunk changed: %#v", doc.Chunks[1])
	}
	if got := doc.Chunks[2].Comments; len(got) != 3 ||
		*got[0].Offset != offsetA || *got[1].Offset != offsetA || *got[2].Offset != offsetB {
		t.Fatalf("comments = %#v", got)
	}
	if got := doc.Chunks[3].StackPoints; len(got) != 2 || got[0] != points[0] || got[1] != points[1] {
		t.Fatalf("stack points = %#v", got)
	}
	if got := *doc.Chunks[4].ElapsedSeconds; got != 123 {
		t.Fatalf("elapsed = %d", got)
	}
}

func TestApplyPatchTypeExtraRawRemoveAndAppend(t *testing.T) {
	offset := uint32(9)
	var raw protocol.Encoder
	appendChunk(&raw, KeyFunctionComment, []byte("remove me"))
	appendChunk(&raw, KeyFrameDescription, []byte{1, 2})
	extra := []Comment{
		{Offset: &offset, Type: "anterior", Text: "before"},
		{Offset: &offset, Type: "posterior", Text: "after"},
	}
	patched, err := ApplyPatch(raw.Payload(), PatchRequest{Mutations: []Mutation{
		{Operation: "remove", Index: intPointer(0)},
		{Operation: "set", Index: intPointer(0), Payload: stringPointer("cafe")},
		{Operation: "append", Code: uint32Pointer(KeyType), Type: &TypeInfo{Source: 1, Type: "0c", Fields: "aabb"}},
		{Operation: "append", Code: uint32Pointer(KeyExtraComments), Comments: &extra},
		{Operation: "append", Code: uint32Pointer(88), Payload: stringPointer("00ff")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Decode(patched)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Chunks) != 4 || doc.Chunks[0].Index != 0 || doc.Chunks[0].Payload != "cafe" {
		t.Fatalf("remove/set result = %#v", doc.Chunks)
	}
	if doc.Chunks[1].Type == nil || doc.Chunks[1].Type.Type != "0c" || doc.Chunks[1].Type.Fields != "aabb" {
		t.Fatalf("type = %#v", doc.Chunks[1])
	}
	if got := doc.Chunks[2].Comments; len(got) != 2 ||
		got[0].Type != "anterior" || got[1].Type != "posterior" {
		t.Fatalf("extra comments = %#v", got)
	}
	if doc.Chunks[3].Code != 88 || doc.Chunks[3].Payload != "00ff" {
		t.Fatalf("unknown append = %#v", doc.Chunks[3])
	}
}

func TestApplyPatchValidation(t *testing.T) {
	var raw protocol.Encoder
	appendChunk(&raw, KeyFunctionComment, []byte("x"))
	emptyComments := []Comment{}
	badCommentOffset := []Comment{{Text: "x"}}
	offset := uint32(1)
	badCommentType := []Comment{{Offset: &offset, Type: "anterior", Text: "x"}}
	duplicateExtra := []Comment{
		{Offset: &offset, Type: "anterior", Text: "one"},
		{Offset: &offset, Type: "anterior", Text: "two"},
	}
	duplicateEmptyExtra := []Comment{
		{Offset: &offset, Type: "posterior", Text: ""},
		{Offset: &offset, Type: "posterior", Text: ""},
	}
	tests := []struct {
		name    string
		request PatchRequest
		want    string
	}{
		{"empty", PatchRequest{}, "at least one"},
		{"bad operation", PatchRequest{Mutations: []Mutation{{Operation: "wat"}}}, "operation"},
		{"set missing index", PatchRequest{Mutations: []Mutation{{Operation: "set", Text: stringPointer("x")}}}, "index"},
		{"set bad index", PatchRequest{Mutations: []Mutation{{Operation: "set", Index: intPointer(9), Text: stringPointer("x")}}}, "index"},
		{"set code change", PatchRequest{Mutations: []Mutation{{Operation: "set", Index: intPointer(0), Code: uint32Pointer(4), Text: stringPointer("x")}}}, "cannot change"},
		{"remove value", PatchRequest{Mutations: []Mutation{{Operation: "remove", Index: intPointer(0), Text: stringPointer("x")}}}, "cannot contain"},
		{"append no code", PatchRequest{Mutations: []Mutation{{Operation: "append", Text: stringPointer("x")}}}, "non-zero code"},
		{"append index", PatchRequest{Mutations: []Mutation{{Operation: "append", Index: intPointer(0), Code: uint32Pointer(3), Text: stringPointer("x")}}}, "no index"},
		{"two values", PatchRequest{Mutations: []Mutation{{Operation: "set", Index: intPointer(0), Text: stringPointer("x"), Payload: stringPointer("00")}}}, "exactly one"},
		{"wrong typed value", PatchRequest{Mutations: []Mutation{{Operation: "set", Index: intPointer(0), ElapsedSeconds: int64Pointer(1)}}}, "text is required"},
		{"bad payload", PatchRequest{Mutations: []Mutation{{Operation: "set", Index: intPointer(0), Payload: stringPointer("xyz")}}}, "hexadecimal"},
		{"opaque typed", PatchRequest{Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(99), Text: stringPointer("x")}}}, "payload is required"},
		{"type bad type", PatchRequest{Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(1), Type: &TypeInfo{Type: "x"}}}}, "type must"},
		{"type bad fields", PatchRequest{Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(1), Type: &TypeInfo{Fields: "x"}}}}, "fields must"},
		{"comment offset", PatchRequest{Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(5), Comments: &badCommentOffset}}}, "offset"},
		{"comment type", PatchRequest{Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(5), Comments: &badCommentType}}}, "instruction"},
		{"extra type", PatchRequest{Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(7), Comments: &badCommentType}}}, ""},
		{"duplicate extra", PatchRequest{Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(7), Comments: &duplicateExtra}}}, "duplicates"},
		{"duplicate empty extra", PatchRequest{Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(7), Comments: &duplicateEmptyExtra}}}, "duplicates"},
		{"empty comments valid", PatchRequest{Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(5), Comments: &emptyComments}}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ApplyPatch(raw.Payload(), tt.request)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestApplyPatchMalformedContainerAndChunkLimit(t *testing.T) {
	if _, err := ApplyPatch([]byte{0xc0}, PatchRequest{
		Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(3), Text: stringPointer("x")}},
	}); err == nil {
		t.Fatal("malformed container accepted")
	}

	var raw protocol.Encoder
	for range maxMetadataChunks {
		appendChunk(&raw, 99, nil)
	}
	if _, err := ApplyPatch(raw.Payload(), PatchRequest{
		Mutations: []Mutation{{Operation: "append", Code: uint32Pointer(99), Payload: stringPointer("")}},
	}); err == nil || !strings.Contains(err.Error(), "cannot exceed") {
		t.Fatalf("chunk limit error = %v", err)
	}
}

func TestSemanticFieldsAndDiff(t *testing.T) {
	var before, after protocol.Encoder
	appendChunk(&before, KeyFunctionComment, []byte("before"))
	appendChunk(&before, 99, []byte{1})
	appendChunk(&after, KeyFunctionComment, []byte("after"))
	appendChunk(&after, KeyFunctionComment, []byte("second"))
	appendChunk(&after, 99, []byte{1})

	fields := SemanticFields(before.Payload())
	if len(fields) != 2 || fields[0].Field != "metadata.function_comment" ||
		fields[0].Value != "before" || fields[1].Field != "metadata.unknown_99" {
		t.Fatalf("semantic fields = %#v", fields)
	}
	diff := SemanticDiff(before.Payload(), after.Payload())
	if len(diff) != 2 || diff[0].Field != "metadata.function_comment" ||
		diff[0].Before != "before" || diff[0].After != "after" ||
		diff[1].Field != "metadata.function_comment[2]" || diff[1].Before != nil ||
		diff[1].After != "second" {
		t.Fatalf("semantic diff = %#v", diff)
	}
	if got := SemanticDiff(before.Payload(), append([]byte(nil), before.Payload()...)); got != nil {
		t.Fatalf("identical semantic diff = %#v", got)
	}

	malformed := SemanticFields([]byte{0xc0})
	if len(malformed) != 1 || malformed[0].Field != "metadata.parse_error" {
		t.Fatalf("malformed semantic fields = %#v", malformed)
	}
}

func TestPatchNoUnexpectedRawChanges(t *testing.T) {
	var raw protocol.Encoder
	appendChunk(&raw, KeyFunctionComment, []byte("same"))
	patched, err := ApplyPatch(raw.Payload(), PatchRequest{
		Mutations: []Mutation{{Operation: "set", Index: intPointer(0), Text: stringPointer("same")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(patched, raw.Payload()) {
		t.Fatalf("no-op patch changed bytes: %x != %x", patched, raw.Payload())
	}
}
