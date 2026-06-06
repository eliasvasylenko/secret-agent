package server

import (
	"encoding/json"
	"testing"
)

func TestExchangeIORequest_unmarshal(t *testing.T) {
	const body = `{
		"stdin": {"index": 10, "bytes": "aGk=", "closed": false},
		"stdout": {"index": 128},
		"stderr": {}
	}`
	var req ExchangeIORequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Stdin == nil || req.Stdin.Index != 10 || string(req.Stdin.Bytes) != "hi" || req.Stdin.Closed {
		t.Fatalf("stdin = %+v", req.Stdin)
	}
	if req.Stdout == nil || req.Stdout.Index != 128 {
		t.Fatalf("stdout = %+v", req.Stdout)
	}
	if req.Stderr == nil || req.Stderr.Index != 0 {
		t.Fatalf("stderr = %+v", req.Stderr)
	}
}

func TestExchangeIORequest_omitempty(t *testing.T) {
	var req ExchangeIORequest
	data, err := json.Marshal(&req)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{}" {
		t.Fatalf("marshal empty = %s, want {}", data)
	}
}

func TestExchangeBytes_closeOnly(t *testing.T) {
	data, err := json.Marshal(&ExchangeBytes{Index: 42, Closed: true})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"index":42,"closed":true}`
	if string(data) != want {
		t.Fatalf("got %q, want %q", data, want)
	}
}

func TestExchangeIOResponse_marshal(t *testing.T) {
	exit := 0
	resp := ExchangeIOResponse{
		Stdin:    &ExchangeIndex{Index: 15},
		Stdout:   &ExchangeBytes{Index: 0, Bytes: []byte("out"), Closed: false},
		Stderr:   &ExchangeBytes{Index: 64, Closed: true},
		ExitCode: &exit,
	}
	data, err := json.Marshal(&resp)
	if err != nil {
		t.Fatal(err)
	}
	var back ExchangeIOResponse
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if back.Stdin == nil || back.Stdin.Index != 15 {
		t.Fatalf("stdin = %+v", back.Stdin)
	}
	if back.Stdout == nil || string(back.Stdout.Bytes) != "out" || back.Stdout.Index != 0 {
		t.Fatalf("stdout = %+v", back.Stdout)
	}
	if back.Stderr == nil || !back.Stderr.Closed || back.Stderr.Index != 64 {
		t.Fatalf("stderr = %+v", back.Stderr)
	}
	if back.ExitCode == nil || *back.ExitCode != 0 {
		t.Fatalf("exitCode = %+v", back.ExitCode)
	}
}
