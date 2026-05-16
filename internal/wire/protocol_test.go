package wire

import (
	"bytes"
	"encoding/binary"
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

func TestProtocolHelloWireBytes(t *testing.T) {
	hello := ProtocolHello{
		Version:      ProtocolVersion,
		Status:       ProtocolStatusOK,
		Capabilities: ProtocolCapabilityTCP | ProtocolCapabilityPing,
		Message:      "ok",
	}

	var buf bytes.Buffer
	if err := WriteProtocolHello(&buf, hello); err != nil {
		t.Fatalf("WriteProtocolHello returned error: %v", err)
	}

	want := make([]byte, 12)
	copy(want[0:4], []byte(ProtocolHelloMagic))
	want[4] = ProtocolVersion
	want[5] = ProtocolStatusOK
	binary.BigEndian.PutUint16(want[6:8], 2)
	binary.BigEndian.PutUint32(want[8:12], ProtocolCapabilityTCP|ProtocolCapabilityPing)
	want = append(want, []byte("ok")...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("wire bytes = %x, want %x", buf.Bytes(), want)
	}

	got, err := ReadProtocolHello(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadProtocolHello returned error: %v", err)
	}
	if got != hello {
		t.Fatalf("hello = %+v, want %+v", got, hello)
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
