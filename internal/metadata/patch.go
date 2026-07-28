package metadata

import (
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/segfaultd/lux/internal/protocol"
)

const maxMetadataChunks = 4096

type PatchRequest struct {
	Mutations []Mutation `json:"mutations"`
}

type Mutation struct {
	Operation      string        `json:"operation"`
	Index          *int          `json:"index,omitempty"`
	Code           *uint32       `json:"code,omitempty"`
	Payload        *string       `json:"payload,omitempty"`
	Text           *string       `json:"text,omitempty"`
	ElapsedSeconds *int64        `json:"elapsed_seconds,omitempty"`
	Type           *TypeInfo     `json:"type,omitempty"`
	Comments       *[]Comment    `json:"comments,omitempty"`
	StackPoints    *[]StackPoint `json:"stack_points,omitempty"`
}

type SemanticField struct {
	Field string `json:"field"`
	Value any    `json:"value"`
}

type SemanticDifference struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

// ApplyPatch edits decoded fields while retaining every untouched chunk,
// including chunks unknown to this Lux version, byte-for-byte.
func ApplyPatch(data []byte, request PatchRequest) ([]byte, error) {
	doc, err := Decode(data)
	if err != nil {
		return nil, err
	}
	if len(request.Mutations) == 0 {
		return nil, fmt.Errorf("at least one mutation is required")
	}
	for mutationIndex, mutation := range request.Mutations {
		switch mutation.Operation {
		case "set":
			if mutation.Index == nil || *mutation.Index < 0 || *mutation.Index >= len(doc.Chunks) {
				return nil, fmt.Errorf("mutation %d has an invalid chunk index", mutationIndex)
			}
			if mutation.Code != nil && *mutation.Code != doc.Chunks[*mutation.Index].Code {
				return nil, fmt.Errorf("mutation %d cannot change a chunk code", mutationIndex)
			}
			payload, err := encodeMutationValue(doc.Chunks[*mutation.Index].Code, mutation)
			if err != nil {
				return nil, fmt.Errorf("mutation %d: %w", mutationIndex, err)
			}
			doc.Chunks[*mutation.Index] = decodeChunk(*mutation.Index, doc.Chunks[*mutation.Index].Code, payload)
		case "remove":
			if mutation.Index == nil || *mutation.Index < 0 || *mutation.Index >= len(doc.Chunks) {
				return nil, fmt.Errorf("mutation %d has an invalid chunk index", mutationIndex)
			}
			if countMutationValues(mutation) != 0 || mutation.Code != nil {
				return nil, fmt.Errorf("mutation %d remove cannot contain a value or code", mutationIndex)
			}
			doc.Chunks = append(doc.Chunks[:*mutation.Index], doc.Chunks[*mutation.Index+1:]...)
			reindex(doc.Chunks)
		case "append":
			if mutation.Index != nil || mutation.Code == nil || *mutation.Code == 0 {
				return nil, fmt.Errorf("mutation %d append requires a non-zero code and no index", mutationIndex)
			}
			if len(doc.Chunks) >= maxMetadataChunks {
				return nil, fmt.Errorf("metadata cannot exceed %d chunks", maxMetadataChunks)
			}
			payload, err := encodeMutationValue(*mutation.Code, mutation)
			if err != nil {
				return nil, fmt.Errorf("mutation %d: %w", mutationIndex, err)
			}
			doc.Chunks = append(doc.Chunks, decodeChunk(len(doc.Chunks), *mutation.Code, payload))
		default:
			return nil, fmt.Errorf("mutation %d operation must be set, remove, or append", mutationIndex)
		}
	}
	return Encode(doc)
}

func encodeMutationValue(code uint32, mutation Mutation) ([]byte, error) {
	if countMutationValues(mutation) != 1 {
		return nil, fmt.Errorf("exactly one value is required")
	}
	if mutation.Payload != nil {
		payload, err := hex.DecodeString(*mutation.Payload)
		if err != nil {
			return nil, fmt.Errorf("payload must be hexadecimal")
		}
		return payload, nil
	}
	switch code {
	case KeyType:
		if mutation.Type == nil {
			return nil, fmt.Errorf("type value is required for %s", keyDescriptions[code].name)
		}
		return encodeType(*mutation.Type)
	case KeyDecompilerElapsed:
		if mutation.ElapsedSeconds == nil {
			return nil, fmt.Errorf("elapsed_seconds is required for %s", keyDescriptions[code].name)
		}
		var out protocol.Encoder
		out.DQ(uint64(*mutation.ElapsedSeconds))
		return append([]byte(nil), out.Payload()...), nil
	case KeyFunctionComment, KeyFunctionRepeatComment:
		if mutation.Text == nil {
			return nil, fmt.Errorf("text is required for %s", keyDescriptions[code].name)
		}
		return []byte(*mutation.Text), nil
	case KeyInstructionComments, KeyInstructionRepeat:
		if mutation.Comments == nil {
			return nil, fmt.Errorf("comments are required for %s", keyDescriptions[code].name)
		}
		return encodeInstructionComments(*mutation.Comments)
	case KeyExtraComments:
		if mutation.Comments == nil {
			return nil, fmt.Errorf("comments are required for %s", keyDescriptions[code].name)
		}
		return encodeExtraComments(*mutation.Comments)
	case KeyUserStackPoints:
		if mutation.StackPoints == nil {
			return nil, fmt.Errorf("stack_points are required for %s", keyDescriptions[code].name)
		}
		return encodeStackPoints(*mutation.StackPoints), nil
	default:
		return nil, fmt.Errorf("payload is required for opaque chunk %d", code)
	}
}

func countMutationValues(mutation Mutation) int {
	count := 0
	for _, present := range []bool{
		mutation.Payload != nil,
		mutation.Text != nil,
		mutation.ElapsedSeconds != nil,
		mutation.Type != nil,
		mutation.Comments != nil,
		mutation.StackPoints != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

func encodeType(value TypeInfo) ([]byte, error) {
	serializedType, err := hex.DecodeString(value.Type)
	if err != nil {
		return nil, fmt.Errorf("type must be hexadecimal")
	}
	fields, err := hex.DecodeString(value.Fields)
	if err != nil {
		return nil, fmt.Errorf("fields must be hexadecimal")
	}
	payload := make([]byte, 1, 2+len(serializedType)+len(fields))
	payload[0] = value.Source
	payload = append(payload, serializedType...)
	if len(fields) > 0 {
		payload = append(payload, 0)
		payload = append(payload, fields...)
	}
	return payload, nil
}

type offsetValue[T any] struct {
	offset uint32
	value  T
}

func encodeOffsetValues[T any](values []offsetValue[T], appendValue func(*protocol.Encoder, T)) []byte {
	var out protocol.Encoder
	if len(values) == 0 {
		out.DD(0)
		return append([]byte(nil), out.Payload()...)
	}
	current := values[0].offset
	out.DD(current)
	out.DD(0)
	appendValue(&out, values[0].value)
	for _, item := range values[1:] {
		if item.offset > current {
			out.DD(item.offset - current)
		} else {
			out.DD(0)
			out.DD(item.offset)
			out.DD(0)
		}
		appendValue(&out, item.value)
		current = item.offset
	}
	return append([]byte(nil), out.Payload()...)
}

func encodeInstructionComments(comments []Comment) ([]byte, error) {
	values := make([]offsetValue[string], 0, len(comments))
	for i, comment := range comments {
		if comment.Offset == nil {
			return nil, fmt.Errorf("comment %d offset is required", i)
		}
		if comment.Type != "" && comment.Type != "instruction" && comment.Type != "byte" {
			return nil, fmt.Errorf("comment %d must be an instruction comment", i)
		}
		values = append(values, offsetValue[string]{offset: *comment.Offset, value: comment.Text})
	}
	return encodeOffsetValues(values, func(out *protocol.Encoder, text string) {
		out.Bytes([]byte(text))
	}), nil
}

type extraComment struct {
	anterior  string
	posterior string
}

func encodeExtraComments(comments []Comment) ([]byte, error) {
	var values []offsetValue[extraComment]
	positions := make(map[uint32]int)
	for i, comment := range comments {
		if comment.Offset == nil {
			return nil, fmt.Errorf("comment %d offset is required", i)
		}
		if comment.Type != "anterior" && comment.Type != "posterior" {
			return nil, fmt.Errorf("comment %d must be anterior or posterior", i)
		}
		position, exists := positions[*comment.Offset]
		if !exists {
			position = len(values)
			positions[*comment.Offset] = position
			values = append(values, offsetValue[extraComment]{offset: *comment.Offset})
		}
		value := &values[position].value
		if comment.Type == "anterior" {
			if value.anterior != "" {
				return nil, fmt.Errorf("comment %d duplicates an anterior comment at offset %d", i, *comment.Offset)
			}
			value.anterior = comment.Text
		} else {
			if value.posterior != "" {
				return nil, fmt.Errorf("comment %d duplicates a posterior comment at offset %d", i, *comment.Offset)
			}
			value.posterior = comment.Text
		}
	}
	return encodeOffsetValues(values, func(out *protocol.Encoder, comment extraComment) {
		out.Bytes([]byte(comment.anterior))
		out.Bytes([]byte(comment.posterior))
	}), nil
}

func encodeStackPoints(points []StackPoint) []byte {
	values := make([]offsetValue[int64], len(points))
	for i, point := range points {
		values[i] = offsetValue[int64]{offset: point.Offset, value: point.Delta}
	}
	return encodeOffsetValues(values, func(out *protocol.Encoder, delta int64) {
		out.DQ(uint64(delta))
	})
}

func reindex(chunks []Chunk) {
	for i := range chunks {
		chunks[i].Index = i
	}
}

// SemanticFields returns stable, field-oriented values suitable for API
// display and history comparisons.
func SemanticFields(data []byte) []SemanticField {
	doc := Inspect(data)
	occurrences := make(map[string]int)
	fields := make([]SemanticField, 0, len(doc.Chunks)+1)
	for _, chunk := range doc.Chunks {
		base := chunk.Key
		occurrences[base]++
		field := "metadata." + base
		if occurrences[base] > 1 {
			field = fmt.Sprintf("%s[%d]", field, occurrences[base])
		}
		var value any
		switch {
		case chunk.Error != "":
			value = map[string]any{"error": chunk.Error, "payload": chunk.Payload}
		case chunk.Type != nil:
			value = *chunk.Type
		case chunk.ElapsedSeconds != nil:
			value = *chunk.ElapsedSeconds
		case chunk.Text != nil:
			value = *chunk.Text
		case chunk.Comments != nil:
			value = chunk.Comments
		case chunk.StackPoints != nil:
			value = chunk.StackPoints
		default:
			value = map[string]any{"size": chunk.Size, "payload": chunk.Payload}
		}
		fields = append(fields, SemanticField{Field: field, Value: value})
	}
	if doc.Error != "" {
		fields = append(fields, SemanticField{
			Field: "metadata.parse_error",
			Value: map[string]any{"error": doc.Error, "size": doc.Size},
		})
	}
	return fields
}

func SemanticDiff(before, after []byte) []SemanticDifference {
	beforeFields := SemanticFields(before)
	afterFields := SemanticFields(after)
	beforeByName := make(map[string]any, len(beforeFields))
	afterByName := make(map[string]any, len(afterFields))
	var order []string
	seen := make(map[string]bool)
	for _, field := range beforeFields {
		beforeByName[field.Field] = field.Value
		order = append(order, field.Field)
		seen[field.Field] = true
	}
	for _, field := range afterFields {
		afterByName[field.Field] = field.Value
		if !seen[field.Field] {
			order = append(order, field.Field)
			seen[field.Field] = true
		}
	}
	var differences []SemanticDifference
	for _, field := range order {
		beforeValue, beforeOK := beforeByName[field]
		afterValue, afterOK := afterByName[field]
		if beforeOK && afterOK && reflect.DeepEqual(beforeValue, afterValue) {
			continue
		}
		difference := SemanticDifference{Field: field}
		if beforeOK {
			difference.Before = beforeValue
		}
		if afterOK {
			difference.After = afterValue
		}
		differences = append(differences, difference)
	}
	return differences
}
