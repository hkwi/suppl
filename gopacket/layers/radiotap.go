package layers

import (
	"encoding/binary"
	"github.com/google/gopacket/layers"
	"hash/crc32"
)

// returns valid dot11 frame without FCS
func FetchDot11FromRadioTap(r *layers.RadioTap) []byte {
	if r.Flags.BadFCS() {
		return nil
	}
	payload := r.Payload
	if r.Flags.Datapad() && len(payload) > 2 {
		if payload[0]&0x0F == 0x08 { // Data
			hdr_length := 24
			if payload[1]&0x03 == 0x03 { // DATA_ADDR_T4; ToDS,FromDS == 1,1
				hdr_length = 30
			}
			if payload[0]&0x80 == 0x80 { // QoS Data
				hdr_length += 2              // QoS control field
				if payload[1]&0x80 == 0x80 { // Order==1 with QoS Data := HT Control
					hdr_length += 4
				}
			}
			// todo: mesh
			if hdr_length%4 != 0 {
				padlen := 4 - hdr_length%4
				payload = make([]byte, len(r.Payload)-padlen)
				copy(payload, r.Payload[:hdr_length])
				copy(payload[hdr_length:], r.Payload[hdr_length+padlen:])
			}
		}
	}
	if r.Flags.FCS() {
		h := crc32.NewIEEE()
		h.Write(payload[:len(payload)-4])
		if binary.LittleEndian.Uint32(payload[len(payload)-4:]) != h.Sum32() {
			return nil
		}
		return payload[:len(payload)-4]
	}
	return payload
}
