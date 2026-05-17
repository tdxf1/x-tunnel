package wire

import (
	"bytes"
	"testing"
)

func TestSmuxOpenHeaderWireBytes(t *testing.T) {
	var buf bytes.Buffer
	const target = "example.com:443"

	if err := WriteSmuxOpenHeader(&buf, StreamKindTCP, 3, target); err != nil {
		t.Fatalf("WriteSmuxOpenHeader returned error: %v", err)
	}

	want := append([]byte{StreamKindTCP, 3, 0, byte(len(target))}, []byte(target)...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("wire bytes = %x, want %x", buf.Bytes(), want)
	}

	kind, strategy, gotTarget, err := ReadSmuxOpenHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadSmuxOpenHeader returned error: %v", err)
	}
	if kind != StreamKindTCP || strategy != 3 || gotTarget != target {
		t.Fatalf("header = kind=%d strategy=%d target=%q", kind, strategy, gotTarget)
	}
}

func TestUDPReplyValidatesAddressAndRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteUDPReply(&buf, "127.0.0.1:53", []byte("dns")); err != nil {
		t.Fatalf("WriteUDPReply returned error: %v", err)
	}
	addr, payload, err := ReadUDPReply(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadUDPReply returned error: %v", err)
	}
	if addr != "127.0.0.1:53" || string(payload) != "dns" {
		t.Fatalf("reply = addr=%q payload=%q", addr, payload)
	}
	if err := WriteUDPReply(&buf, "bad host:53", nil); err == nil {
		t.Fatal("WriteUDPReply accepted malformed address")
	}
}
