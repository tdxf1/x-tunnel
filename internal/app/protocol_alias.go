package app

import (
	"io"

	"x-tunnel/internal/wire"
)

const (
	streamKindTCP   = wire.StreamKindTCP
	streamKindUDP   = wire.StreamKindUDP
	streamKindPing  = wire.StreamKindPing
	streamKindHello = wire.StreamKindHello

	protocolVersion                    = wire.ProtocolVersion
	protocolStatusOK                   = wire.ProtocolStatusOK
	protocolStatusUnsupportedVersion   = wire.ProtocolStatusUnsupportedVersion
	protocolStatusNoCommonCapabilities = wire.ProtocolStatusNoCommonCapabilities

	protocolCapabilityTCP            = wire.ProtocolCapabilityTCP
	protocolCapabilityUDP            = wire.ProtocolCapabilityUDP
	protocolCapabilityPing           = wire.ProtocolCapabilityPing
	protocolCapabilityIPStrategy     = wire.ProtocolCapabilityIPStrategy
	protocolCapabilityTCPStatus      = wire.ProtocolCapabilityTCPStatus
	protocolCapabilityUDPStatus      = wire.ProtocolCapabilityUDPStatus
	protocolCapabilityOpenStatusCode = wire.ProtocolCapabilityOpenStatusCode

	tcpOpenStatusOK    = wire.TCPOpenStatusOK
	tcpOpenStatusError = wire.TCPOpenStatusError
	udpOpenStatusOK    = wire.UDPOpenStatusOK
	udpOpenStatusError = wire.UDPOpenStatusError

	openStatusCodeNone          = wire.OpenStatusCodeNone
	openStatusCodeBadTarget     = wire.OpenStatusCodeBadTarget
	openStatusCodePolicyDenied  = wire.OpenStatusCodePolicyDenied
	openStatusCodeDialFailed    = wire.OpenStatusCodeDialFailed
	openStatusCodeResourceLimit = wire.OpenStatusCodeResourceLimit

	protocolHelloMagic  = wire.ProtocolHelloMagic
	maxProtocolFieldLen = wire.MaxProtocolFieldLen
)

type ProtocolHello = wire.ProtocolHello

func isSupportedStreamKind(kind byte) bool { return wire.IsSupportedStreamKind(kind) }

func currentProtocolCapabilities() uint32 { return wire.CurrentProtocolCapabilities() }

func requiredProtocolCapabilities() uint32 { return wire.RequiredProtocolCapabilities() }

func currentProtocolHello() ProtocolHello { return wire.CurrentProtocolHello() }

func writeProtocolHello(w io.Writer, hello ProtocolHello) error {
	return wire.WriteProtocolHello(w, hello)
}

func readProtocolHello(r io.Reader) (ProtocolHello, error) { return wire.ReadProtocolHello(r) }

func negotiateProtocolHello(clientHello ProtocolHello) ProtocolHello {
	return wire.NegotiateProtocolHello(clientHello)
}

func writeTCPOpenStatus(w io.Writer, status byte, message string) error {
	return wire.WriteTCPOpenStatus(w, status, message)
}

func readTCPOpenStatus(r io.Reader) (byte, string, error) { return wire.ReadTCPOpenStatus(r) }

func writeTCPOpenStatusCode(w io.Writer, status byte, code byte, message string) error {
	return wire.WriteTCPOpenStatusCode(w, status, code, message)
}

func readTCPOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	return wire.ReadTCPOpenStatusCode(r)
}

func writeUDPOpenStatus(w io.Writer, status byte, message string) error {
	return wire.WriteUDPOpenStatus(w, status, message)
}

func readUDPOpenStatus(r io.Reader) (byte, string, error) { return wire.ReadUDPOpenStatus(r) }

func writeUDPOpenStatusCode(w io.Writer, status byte, code byte, message string) error {
	return wire.WriteUDPOpenStatusCode(w, status, code, message)
}

func readUDPOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	return wire.ReadUDPOpenStatusCode(r)
}

func writeOpenStatus(w io.Writer, fieldName string, status byte, message string) error {
	return wire.WriteOpenStatus(w, fieldName, status, message)
}

func readOpenStatus(r io.Reader) (byte, string, error) { return wire.ReadOpenStatus(r) }

func writeOpenStatusCode(w io.Writer, fieldName string, status byte, code byte, message string) error {
	return wire.WriteOpenStatusCode(w, fieldName, status, code, message)
}

func readOpenStatusCode(r io.Reader) (byte, byte, string, error) {
	return wire.ReadOpenStatusCode(r)
}

func readSmuxOpenHeader(r io.Reader) (byte, byte, string, error) {
	return wire.ReadSmuxOpenHeader(r)
}

func writeSmuxOpenHeader(w io.Writer, kind byte, strategy byte, target string) error {
	return wire.WriteSmuxOpenHeader(w, kind, strategy, target)
}

func writeChunk(w io.Writer, b []byte) error { return wire.WriteChunk(w, b) }

func readChunk(r io.Reader) ([]byte, error) { return wire.ReadChunk(r) }

func writeUDPReply(w io.Writer, addr string, payload []byte) error {
	return wire.WriteUDPReply(w, addr, payload)
}

func readUDPReply(r io.Reader) (string, []byte, error) { return wire.ReadUDPReply(r) }

func validateProtocolFieldLen(name string, length int) error {
	return wire.ValidateProtocolFieldLen(name, length)
}

func writeAll(w io.Writer, b []byte) error { return wire.WriteAll(w, b) }

func writeAllCount(w io.Writer, b []byte) (int, error) { return wire.WriteAllCount(w, b) }
