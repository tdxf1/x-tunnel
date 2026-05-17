package wire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func fixedChannelInit() ChannelInit {
	sessionID := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	nonce := bytes.Repeat([]byte{0xa5}, 32)
	return ChannelInit{
		SessionID:    sessionID,
		ChannelID:    7,
		ClientNonce:  nonce,
		Timestamp:    1_700_000_000,
		Capabilities: currentProtocolCapabilitiesV2(),
	}
}

func TestV2FrameWireBytes(t *testing.T) {
	var buf bytes.Buffer
	if err := writeV2Frame(&buf, V2Frame{
		Type:    v2FrameTypeChannelInit,
		Version: protocolV2Version,
		Flags:   0x1234,
		Body:    []byte("abc"),
	}); err != nil {
		t.Fatalf("writeV2Frame returned error: %v", err)
	}

	want := []byte{v2FrameTypeChannelInit, protocolV2Version, 0x12, 0x34, 0, 0, 0, 3, 'a', 'b', 'c'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("v2 frame bytes = %x, want %x", buf.Bytes(), want)
	}

	got, err := readV2Frame(bytes.NewReader(buf.Bytes()), maxV2FrameSize)
	if err != nil {
		t.Fatalf("readV2Frame returned error: %v", err)
	}
	if got.Type != v2FrameTypeChannelInit || got.Version != protocolV2Version || got.Flags != 0x1234 || !bytes.Equal(got.Body, []byte("abc")) {
		t.Fatalf("v2 frame = %+v, want type/init version/2 flags/0x1234 body/abc", got)
	}
}

func TestV2TLVRejectsDuplicateAndUnknownCritical(t *testing.T) {
	body, err := encodeV2TLVs([]V2TLV{
		{Type: v2RecordSessionID, Value: bytes.Repeat([]byte{1}, 16)},
		{Type: v2RecordSessionID, Value: bytes.Repeat([]byte{2}, 16)},
	})
	if err != nil {
		t.Fatalf("encode duplicate tlvs: %v", err)
	}
	if _, err := parseV2TLVs(body, map[uint16]bool{v2RecordSessionID: true}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("parse duplicate tlvs error = %v, want duplicate rejection", err)
	}

	body, err = encodeV2TLVs([]V2TLV{{Type: 0x9000, Value: []byte("must-understand")}})
	if err != nil {
		t.Fatalf("encode unknown critical tlv: %v", err)
	}
	if _, err := parseV2TLVs(body, map[uint16]bool{v2RecordSessionID: true}); err == nil || !strings.Contains(err.Error(), "unknown critical") {
		t.Fatalf("parse unknown critical tlv error = %v, want critical rejection", err)
	}

	body, err = encodeV2TLVs([]V2TLV{{Type: 0x000f, Value: []byte("ignore")}})
	if err != nil {
		t.Fatalf("encode unknown non-critical tlv: %v", err)
	}
	records, err := parseV2TLVs(body, map[uint16]bool{v2RecordSessionID: true})
	if err != nil {
		t.Fatalf("parse unknown non-critical tlv returned error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("unknown non-critical records = %d, want ignored", len(records))
	}
}

func TestChannelInitAuthProofRoundTrip(t *testing.T) {
	init := fixedChannelInit()
	proof, err := computeV2AuthProof("secret-token", "edge.example.com", "/tunnel", init)
	if err != nil {
		t.Fatalf("computeV2AuthProof returned error: %v", err)
	}
	init.AuthProof = proof
	if !verifyV2AuthProof("secret-token", "edge.example.com", "/tunnel", init) {
		t.Fatal("verifyV2AuthProof rejected valid proof")
	}
	if verifyV2AuthProof("wrong-token", "edge.example.com", "/tunnel", init) {
		t.Fatal("verifyV2AuthProof accepted wrong token")
	}
	if verifyV2AuthProof("secret-token", "other.example.com", "/tunnel", init) {
		t.Fatal("verifyV2AuthProof accepted wrong server name")
	}

	var buf bytes.Buffer
	if err := writeChannelInit(&buf, init); err != nil {
		t.Fatalf("writeChannelInit returned error: %v", err)
	}
	got, err := readChannelInit(bytes.NewReader(buf.Bytes()), maxV2FrameSize)
	if err != nil {
		t.Fatalf("readChannelInit returned error: %v", err)
	}
	if got.ChannelID != init.ChannelID || got.Timestamp != init.Timestamp || got.Capabilities != init.Capabilities {
		t.Fatalf("channel init scalars = %+v, want %+v", got, init)
	}
	if !bytes.Equal(got.SessionID, init.SessionID) || !bytes.Equal(got.ClientNonce, init.ClientNonce) || !bytes.Equal(got.AuthProof, init.AuthProof) {
		t.Fatalf("channel init byte fields did not round-trip")
	}
}

func TestChannelAcceptAndRejectRoundTrip(t *testing.T) {
	accept := ChannelAccept{
		Capabilities: currentProtocolCapabilitiesV2(),
		ServerNonce:  bytes.Repeat([]byte{0x5a}, 32),
		ServerTime:   1_700_000_001,
		MaxFrameSize: 4096,
		MaxStreams:   128,
		Message:      "ok",
	}
	var buf bytes.Buffer
	if err := writeChannelAccept(&buf, accept); err != nil {
		t.Fatalf("writeChannelAccept returned error: %v", err)
	}
	gotAccept, gotReject, err := readChannelAcceptOrReject(bytes.NewReader(buf.Bytes()), maxV2FrameSize)
	if err != nil {
		t.Fatalf("readChannelAcceptOrReject accept returned error: %v", err)
	}
	if gotReject.Code != 0 {
		t.Fatalf("reject = %+v, want zero value for accept frame", gotReject)
	}
	if gotAccept.Capabilities != accept.Capabilities || gotAccept.ServerTime != accept.ServerTime || gotAccept.MaxFrameSize != accept.MaxFrameSize || gotAccept.MaxStreams != accept.MaxStreams || gotAccept.Message != accept.Message {
		t.Fatalf("accept = %+v, want %+v", gotAccept, accept)
	}
	if !bytes.Equal(gotAccept.ServerNonce, accept.ServerNonce) {
		t.Fatalf("accept nonce did not round-trip")
	}

	buf.Reset()
	reject := ChannelReject{Code: v2RejectAuthenticationFailed, Message: "bad proof"}
	if err := writeChannelReject(&buf, reject); err != nil {
		t.Fatalf("writeChannelReject returned error: %v", err)
	}
	gotAccept, gotReject, err = readChannelAcceptOrReject(bytes.NewReader(buf.Bytes()), maxV2FrameSize)
	if err != nil {
		t.Fatalf("readChannelAcceptOrReject reject returned error: %v", err)
	}
	if gotAccept.Capabilities != 0 {
		t.Fatalf("accept = %+v, want zero value for reject frame", gotAccept)
	}
	if gotReject != reject {
		t.Fatalf("reject = %+v, want %+v", gotReject, reject)
	}
}

func TestV2TimestampAndCapabilityValidation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if !validateChannelInitTimestamp(now, now.Unix(), time.Minute) {
		t.Fatal("timestamp validator rejected current timestamp")
	}
	if validateChannelInitTimestamp(now, now.Add(2*time.Minute).Unix(), time.Minute) {
		t.Fatal("timestamp validator accepted future timestamp outside skew")
	}
	if validateChannelInitTimestamp(now, now.Add(-2*time.Minute).Unix(), time.Minute) {
		t.Fatal("timestamp validator accepted old timestamp outside skew")
	}
	if !validateChannelInitTimestamp(now, now.Add(24*time.Hour).Unix(), 0) {
		t.Fatal("timestamp validator rejected timestamp when skew disabled")
	}

	caps, code, message := negotiateProtocolCapabilitiesV2(currentProtocolCapabilitiesV2())
	if code != 0 || message != "" || caps != currentProtocolCapabilitiesV2() {
		t.Fatalf("v2 capability negotiation = caps 0x%x code %d message %q, want current caps", caps, code, message)
	}
	missingOpenStatusCode := currentProtocolCapabilitiesV2() &^ uint64(protocolCapabilityOpenStatusCode)
	caps, code, message = negotiateProtocolCapabilitiesV2(missingOpenStatusCode)
	if caps != 0 || code != v2RejectMissingRequiredCapability || message == "" {
		t.Fatalf("v2 missing capability negotiation = caps 0x%x code %d message %q, want missing required rejection", caps, code, message)
	}
}

func TestDecodeChannelInitRejectsDuplicateRequiredRecord(t *testing.T) {
	init := fixedChannelInit()
	proof, err := computeV2AuthProof("secret-token", "edge.example.com", "/tunnel", init)
	if err != nil {
		t.Fatalf("computeV2AuthProof returned error: %v", err)
	}
	init.AuthProof = proof
	body, err := encodeChannelInit(init)
	if err != nil {
		t.Fatalf("encodeChannelInit returned error: %v", err)
	}
	var duplicate bytes.Buffer
	caps := make([]byte, 8)
	binary.BigEndian.PutUint64(caps, init.Capabilities)
	if err := writeV2TLV(&duplicate, v2RecordCapabilities, caps); err != nil {
		t.Fatalf("write duplicate capabilities tlv: %v", err)
	}
	body = append(body, duplicate.Bytes()...)
	if _, err := decodeChannelInit(body); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("decodeChannelInit duplicate error = %v, want duplicate rejection", err)
	}
}

func BenchmarkChannelInitRoundTrip(b *testing.B) {
	init := fixedChannelInit()
	proof, err := computeV2AuthProof("secret-token", "edge.example.com", "/tunnel", init)
	if err != nil {
		b.Fatal(err)
	}
	init.AuthProof = proof
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := writeChannelInit(&buf, init); err != nil {
			b.Fatal(err)
		}
		if _, err := readChannelInit(&buf, maxV2FrameSize); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeV2AuthProof(b *testing.B) {
	init := fixedChannelInit()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := computeV2AuthProof("secret-token", "edge.example.com", "/tunnel", init); err != nil {
			b.Fatal(err)
		}
	}
}
