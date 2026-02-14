package marshal

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSON(t *testing.T) {
	b, err := JSON(map[string]string{"x": "<script>"})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, "<script>") {
		t.Errorf("expected HTML not escaped, got %q", s)
	}
}

func TestJSONIndent(t *testing.T) {
	b, err := JSONIndent(map[string]string{"a": "b"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out["a"] != "b" {
		t.Errorf("round-trip: got %q", out["a"])
	}
	if !strings.Contains(string(b), "\n  ") {
		t.Errorf("expected indented output")
	}
}
