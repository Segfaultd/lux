package metadata

import (
	"encoding/hex"
	"fmt"
	"unicode/utf8"

	"github.com/segfaultd/lux/internal/protocol"
)

const (
	KeyType                  uint32 = 1
	KeyDecompilerElapsed     uint32 = 2
	KeyFunctionComment       uint32 = 3
	KeyFunctionRepeatComment uint32 = 4
	KeyInstructionComments   uint32 = 5
	KeyInstructionRepeat     uint32 = 6
	KeyExtraComments         uint32 = 7
	KeyUserStackPoints       uint32 = 8
	KeyFrameDescription      uint32 = 9
	KeyOperandRepresentation uint32 = 10
	KeyExtendedOperands      uint32 = 11
)

type Document struct {
	Size    int     `json:"size"`
	Chunks  []Chunk `json:"chunks"`
	Summary Summary `json:"summary"`
	Error   string  `json:"error,omitempty"`
}

type Summary struct {
	KnownChunks    int  `json:"known_chunks"`
	UnknownChunks  int  `json:"unknown_chunks"`
	Comments       int  `json:"comments"`
	StackPoints    int  `json:"stack_points"`
	HasType        bool `json:"has_type"`
	HasFrame       bool `json:"has_frame"`
	OperandChunks  int  `json:"operand_chunks"`
	DecodeFailures int  `json:"decode_failures"`
}

type Chunk struct {
	Index          int          `json:"index"`
	Code           uint32       `json:"code"`
	Key            string       `json:"key"`
	Format         string       `json:"format"`
	Known          bool         `json:"known"`
	Editable       bool         `json:"editable"`
	Size           int          `json:"size"`
	Payload        string       `json:"payload"`
	Text           *string      `json:"text,omitempty"`
	ElapsedSeconds *int64       `json:"elapsed_seconds,omitempty"`
	Type           *TypeInfo    `json:"type,omitempty"`
	Comments       []Comment    `json:"comments,omitempty"`
	StackPoints    []StackPoint `json:"stack_points,omitempty"`
	Error          string       `json:"error,omitempty"`
}

type TypeInfo struct {
	Source      uint8  `json:"source"`
	UserDefined bool   `json:"user_defined"`
	Type        string `json:"type"`
	Fields      string `json:"fields,omitempty"`
}

type StackPoint struct {
	Offset uint32 `json:"offset"`
	Delta  int64  `json:"delta"`
}

type keyDescription struct {
	name     string
	format   string
	editable bool
}

var keyDescriptions = map[uint32]keyDescription{
	KeyType:                  {"type", "type", true},
	KeyDecompilerElapsed:     {"decompiler_elapsed", "int64", true},
	KeyFunctionComment:       {"function_comment", "string", true},
	KeyFunctionRepeatComment: {"function_repeatable_comment", "string", true},
	KeyInstructionComments:   {"instruction_comments", "delta_string_list", true},
	KeyInstructionRepeat:     {"instruction_repeatable_comments", "delta_string_list", true},
	KeyExtraComments:         {"extra_comments", "anterior_posterior_list", true},
	KeyUserStackPoints:       {"user_stack_points", "delta_signed_value_list", true},
	KeyFrameDescription:      {"frame_description", "frame_description", false},
	KeyOperandRepresentation: {"operand_representations", "delta_operand_list", false},
	KeyExtendedOperands:      {"extended_operand_representations", "delta_operand_list", false},
}

// Decode splits an IDA metadata blob into lossless chunks and decodes fields
// whose wire grammar is supported. Payload always contains the original bytes,
// including for known chunks, so callers can round-trip data.
func Decode(data []byte) (Document, error) {
	doc := Document{Size: len(data), Chunks: []Chunk{}}
	d := protocol.NewDecoder(data)
	for d.Remaining() > 0 {
		code, err := d.DD()
		if err != nil {
			return doc, fmt.Errorf("metadata chunk %d key: %w", len(doc.Chunks), err)
		}
		payload, err := d.Bytes()
		if err != nil {
			return doc, fmt.Errorf("metadata chunk %d payload: %w", len(doc.Chunks), err)
		}
		chunk := decodeChunk(len(doc.Chunks), code, payload)
		doc.Chunks = append(doc.Chunks, chunk)
		updateSummary(&doc.Summary, chunk)
	}
	return doc, nil
}

// Inspect returns as much structured information as possible for malformed
// administrator-supplied data while keeping strict Decode available to callers.
func Inspect(data []byte) Document {
	doc, err := Decode(data)
	if err != nil {
		doc.Error = err.Error()
	}
	return doc
}

// Encode reproduces the metadata container from a decoded document. An
// unchanged document is byte-for-byte identical, including unknown chunks.
func Encode(doc Document) ([]byte, error) {
	var out protocol.Encoder
	for i, chunk := range doc.Chunks {
		payload, err := hex.DecodeString(chunk.Payload)
		if err != nil {
			return nil, fmt.Errorf("metadata chunk %d payload must be hexadecimal: %w", i, err)
		}
		out.DD(chunk.Code)
		out.Bytes(payload)
	}
	return append([]byte(nil), out.Payload()...), nil
}

func decodeChunk(index int, code uint32, payload []byte) Chunk {
	description, known := keyDescriptions[code]
	if !known {
		description = keyDescription{
			name:   fmt.Sprintf("unknown_%d", code),
			format: "opaque",
		}
	}
	chunk := Chunk{
		Index:    index,
		Code:     code,
		Key:      description.name,
		Format:   description.format,
		Known:    known,
		Editable: description.editable,
		Size:     len(payload),
		Payload:  hex.EncodeToString(payload),
	}
	var err error
	switch code {
	case KeyType:
		chunk.Type, err = decodeType(payload)
	case KeyDecompilerElapsed:
		var value int64
		value, err = decodeInt64(payload)
		if err == nil {
			chunk.ElapsedSeconds = &value
		}
	case KeyFunctionComment, KeyFunctionRepeatComment:
		var text string
		text, err = decodeText(payload)
		if err == nil {
			chunk.Text = &text
		}
	case KeyInstructionComments, KeyInstructionRepeat:
		chunk.Comments, err = decodeInstructionComments(payload, code == KeyInstructionRepeat)
	case KeyExtraComments:
		chunk.Comments, err = decodeExtraComments(payload)
	case KeyUserStackPoints:
		chunk.StackPoints, err = decodeStackPoints(payload)
	}
	if err != nil {
		chunk.Error = err.Error()
	}
	return chunk
}

func decodeType(payload []byte) (*TypeInfo, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("type payload is empty")
	}
	typeInfo := &TypeInfo{
		Source:      payload[0],
		UserDefined: payload[0] != 0,
	}
	serialized := payload[1:]
	for i, value := range serialized {
		if value == 0 {
			typeInfo.Type = hex.EncodeToString(serialized[:i])
			typeInfo.Fields = hex.EncodeToString(serialized[i+1:])
			return typeInfo, nil
		}
	}
	typeInfo.Type = hex.EncodeToString(serialized)
	return typeInfo, nil
}

func decodeInt64(payload []byte) (int64, error) {
	d := protocol.NewDecoder(payload)
	value, err := d.DQ()
	if err != nil {
		return 0, err
	}
	if d.Remaining() != 0 {
		return 0, fmt.Errorf("int64 payload has %d trailing bytes", d.Remaining())
	}
	return int64(value), nil
}

func decodeText(payload []byte) (string, error) {
	if !utf8.Valid(payload) {
		return "", fmt.Errorf("string payload is not valid UTF-8")
	}
	return string(payload), nil
}

func decodeInstructionComments(payload []byte, repeatable bool) ([]Comment, error) {
	return parseOffsetSequence(payload, func(d *protocol.Decoder) ([]Comment, error) {
		raw, err := d.Bytes()
		if err != nil {
			return nil, err
		}
		text, err := decodeText(raw)
		if err != nil {
			return nil, err
		}
		return []Comment{{Type: "instruction", Repeatable: repeatable, Text: text}}, nil
	})
}

func decodeExtraComments(payload []byte) ([]Comment, error) {
	return parseOffsetSequence(payload, func(d *protocol.Decoder) ([]Comment, error) {
		anterior, err := d.Bytes()
		if err != nil {
			return nil, err
		}
		posterior, err := d.Bytes()
		if err != nil {
			return nil, err
		}
		before, err := decodeText(anterior)
		if err != nil {
			return nil, err
		}
		after, err := decodeText(posterior)
		if err != nil {
			return nil, err
		}
		out := make([]Comment, 0, 2)
		if before != "" {
			out = append(out, Comment{Type: "anterior", Text: before})
		}
		if after != "" {
			out = append(out, Comment{Type: "posterior", Text: after})
		}
		return out, nil
	})
}

func decodeStackPoints(payload []byte) ([]StackPoint, error) {
	d := protocol.NewDecoder(payload)
	offset, err := d.DD()
	if err != nil {
		return nil, err
	}
	reset := true
	var out []StackPoint
	for d.Remaining() > 0 {
		diff, err := d.DD()
		if err != nil {
			return nil, err
		}
		if diff > 0 || reset {
			offset += diff
			rawDelta, err := d.DQ()
			if err != nil {
				return nil, err
			}
			out = append(out, StackPoint{Offset: offset, Delta: int64(rawDelta)})
			reset = false
		} else {
			offset, err = d.DD()
			if err != nil {
				return nil, err
			}
			reset = true
		}
	}
	return out, nil
}

func updateSummary(summary *Summary, chunk Chunk) {
	if chunk.Known {
		summary.KnownChunks++
	} else {
		summary.UnknownChunks++
	}
	if chunk.Error != "" {
		summary.DecodeFailures++
	}
	summary.Comments += len(chunk.Comments)
	if (chunk.Code == KeyFunctionComment || chunk.Code == KeyFunctionRepeatComment) &&
		chunk.Text != nil && *chunk.Text != "" {
		summary.Comments++
	}
	summary.StackPoints += len(chunk.StackPoints)
	switch chunk.Code {
	case KeyType:
		summary.HasType = true
	case KeyFrameDescription:
		summary.HasFrame = true
	case KeyOperandRepresentation, KeyExtendedOperands:
		summary.OperandChunks++
	}
}
