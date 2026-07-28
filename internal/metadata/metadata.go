package metadata

import (
	"fmt"
	"strings"

	"github.com/segfaultd/lux/internal/protocol"
)

type Comment struct {
	Offset     *uint32 `json:"offset,omitempty"`
	Type       string  `json:"type"`
	Repeatable bool    `json:"repeatable,omitempty"`
	Text       string  `json:"text"`
}

func Parse(data []byte) ([]Comment, error) {
	doc, err := Decode(data)
	if err != nil {
		return nil, err
	}
	var comments []Comment
	for _, chunk := range doc.Chunks {
		switch chunk.Code {
		case KeyFunctionComment, KeyFunctionRepeatComment:
			if chunk.Error != "" {
				return nil, fmt.Errorf("metadata chunk %d (%s): %s", chunk.Index, chunk.Key, chunk.Error)
			}
			if chunk.Text != nil && *chunk.Text != "" {
				comments = append(comments, Comment{
					Type:       "function",
					Repeatable: chunk.Code == KeyFunctionRepeatComment,
					Text:       *chunk.Text,
				})
			}
		case KeyInstructionComments, KeyInstructionRepeat, KeyExtraComments:
			if chunk.Error != "" {
				return nil, fmt.Errorf("metadata chunk %d (%s): %s", chunk.Index, chunk.Key, chunk.Error)
			}
			for _, comment := range chunk.Comments {
				if comment.Type == "instruction" {
					comment.Type = "byte"
				}
				comments = append(comments, comment)
			}
		}
	}
	return comments, nil
}

func parseOffsetSequence(data []byte, parse func(*protocol.Decoder) ([]Comment, error)) ([]Comment, error) {
	d := protocol.NewDecoder(data)
	offset, err := d.DD()
	if err != nil {
		return nil, err
	}
	reset := true
	var out []Comment
	for d.Remaining() > 0 {
		diff, err := d.DD()
		if err != nil {
			return nil, err
		}
		if diff > 0 || reset {
			offset += diff
			items, err := parse(d)
			if err != nil {
				return nil, err
			}
			for i := range items {
				v := offset
				items[i].Offset = &v
			}
			out = append(out, items...)
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

func Score(data []byte) uint32 {
	comments, err := Parse(data)
	if err != nil {
		return 0
	}
	var score uint32
	for _, comment := range comments {
		if useful(comment) {
			score += 10
		}
	}
	return score
}

func useful(c Comment) bool {
	if c.Text == "" {
		return false
	}
	switch c.Type {
	case "anterior":
		return !strings.HasPrefix(c.Text, "; Exported entry ")
	case "function":
		return c.Text != "Microsoft VisualC v14 64bit runtime" &&
			c.Text != "Microsoft VisualC 64bit universal runtime"
	case "byte":
		switch c.Text {
		case "Trap to Debugger",
			"switch jump",
			"jump table for switch statement",
			"indirect table for switch statement",
			"Microsoft VisualC v7/14 64bit runtime",
			"Microsoft VisualC v7/14 64bit runtime\nMicrosoft VisualC v14 64bit runtime",
			"Microsoft VisualC v14 64bit runtime":
			return false
		}
		if strings.HasPrefix(c.Text, "jumptable ") && strings.Contains(c.Text, " case") {
			return false
		}
		if strings.HasPrefix(c.Text, "switch ") && strings.HasSuffix(c.Text, " cases ") {
			return false
		}
	}
	return true
}

func ParseBestEffort(data []byte) []Comment {
	v, err := Parse(data)
	if err != nil {
		return []Comment{{Type: "parse-error", Text: fmt.Sprintf("metadata could not be decoded: %v", err)}}
	}
	return v
}
