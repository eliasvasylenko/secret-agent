package marshal

import (
	"bytes"
	"encoding/json"
)

// This is required due to go making the unusual choice to escape certain
// html characters by default when unmarshalling JSON
func JSON(value any) ([]byte, error) {
	return marshalJson(value, false)
}

// This is required due to go making the unusual choice to escape certain
// html characters by default when unmarshalling JSON
func JSONIndent(value any) ([]byte, error) {
	return marshalJson(value, true)
}

func marshalJson(value any, indent bool) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if indent {
		encoder.SetIndent("", "  ")
	}
	err := encoder.Encode(value)
	return buffer.Bytes(), err
}
