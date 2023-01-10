package nex

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"errors"
)

// PacketHpp represents an Hpp packet
type PacketHpp struct {
	Packet
	accessKeySignature []byte
	passwordSignature  []byte
}

// SetAccessKeySignature sets the packet access key signature
func (packet *PacketHpp) SetAccessKeySignature(accessKeySignature string) {
	accessKeySignatureBytes, err := hex.DecodeString(accessKeySignature)
	if err != nil {
		logger.Error("[PacketHpp] Failed to convert AccessKeySignature to bytes")
	}

	packet.accessKeySignature = accessKeySignatureBytes
}

// AccessKeySignature returns the packet access key signature
func (packet *PacketHpp) AccessKeySignature() []byte {
	return packet.accessKeySignature
}

// SetPasswordSignature sets the packet password signature
func (packet *PacketHpp) SetPasswordSignature(passwordSignature string) {
	passwordSignatureBytes, err := hex.DecodeString(passwordSignature)
	if err != nil {
		logger.Error("[PacketHpp] Failed to convert PasswordSignature to bytes")
	}

	packet.passwordSignature = passwordSignatureBytes
}

// PasswordSignature returns the packet password signature
func (packet *PacketHpp) PasswordSignature() []byte {
	return packet.passwordSignature
}

// ValidateAccessKey checks if the access key signature is valid
func (packet *PacketHpp) ValidateAccessKey() {
	accessKey, err := hex.DecodeString(packet.sender.server.AccessKey())
	if err != nil {
		logger.Error("[PacketHpp] Failed to decode access key")
	}

	calculatedAccessKeySignature := packet.calculateSignature(packet.Payload(), accessKey)
	if !bytes.Equal(calculatedAccessKeySignature, packet.AccessKeySignature()) {
		logger.Error("Hpp access key calculated signature did not match")
	}
}

func (packet *PacketHpp) calculateSignature(buffer []byte, key []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(buffer)
	hmac := mac.Sum(nil)

	return hmac
}

// NewPacketHpp returns a new Hpp packet
func NewPacketHpp(client *Client, data []byte) (*PacketHpp, error) {
	packet := NewPacket(client, data)
	packetHpp := PacketHpp{Packet: packet}

	if data != nil {
		packetHpp.SetPayload(data)

		rmcRequest := NewRMCRequest()
		err := rmcRequest.FromBytes(data)
		if err != nil {
			return &PacketHpp{}, errors.New("[Hpp] Error parsing RMC request: " + err.Error())
		}

		packetHpp.rmcRequest = rmcRequest
	}

	return &packetHpp, nil
}
