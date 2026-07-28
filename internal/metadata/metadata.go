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

type chunk struct {
	Code uint32
	Data []byte
}

func Parse(data []byte) ([]Comment, error) {
	d := protocol.NewDecoder(data)
	var comments []Comment
	for d.Remaining() > 0 {
		code, err := d.DD()
		if err != nil {
			return nil, err
		}
		payload, err := d.Bytes()
		if err != nil {
			return nil, err
		}
		c := chunk{Code: code, Data: payload}
		switch c.Code {
		case 3, 4:
			if len(c.Data) > 0 {
				comments = append(comments, Comment{
					Type:       "function",
					Repeatable: c.Code == 4,
					Text:       string(c.Data),
				})
			}
		case 5, 6:
			seq, err := parseOffsetSequence(c.Data, func(d *protocol.Decoder) ([]Comment, error) {
				text, err := d.Bytes()
				if err != nil {
					return nil, err
				}
				return []Comment{{Type: "byte", Repeatable: c.Code == 6, Text: string(text)}}, nil
			})
			if err != nil {
				return nil, err
			}
			comments = append(comments, seq...)
		case 7:
			seq, err := parseOffsetSequence(c.Data, func(d *protocol.Decoder) ([]Comment, error) {
				anterior, err := d.Bytes()
				if err != nil {
					return nil, err
				}
				posterior, err := d.Bytes()
				if err != nil {
					return nil, err
				}
				var out []Comment
				if len(anterior) > 0 {
					out = append(out, Comment{Type: "anterior", Text: string(anterior)})
				}
				if len(posterior) > 0 {
					out = append(out, Comment{Type: "posterior", Text: string(posterior)})
				}
				return out, nil
			})
			if err != nil {
				return nil, err
			}
			comments = append(comments, seq...)
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
