package layers

import (
	"encoding/binary"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"hash/crc32"
	"net"
)

func init() {
	layers.MPLSPayloadDecoder = gopacket.DecodeFunc(decodeMPLS)
	layers.EthernetTypeMetadata[ethernetTypeDot1QSTag] = layers.EthernetTypeMetadata[layers.EthernetTypeDot1Q]
	layers.EthernetTypeMetadata[ethernetTypeDot1QITag] = layers.EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodePBB),
		Name:       "PBB",
		LayerType:  LayerTypePBB,
	}
	layers.EthernetTypeMetadata[ethernetTypeLwapp] = layers.EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeLwapp),
		Name:       "Lwapp",
		LayerType:  LayerTypeLwapp,
	}
}

var (
	LayerTypePBB                 = gopacket.RegisterLayerType(500, gopacket.LayerTypeMetadata{"PBB", gopacket.DecodeFunc(decodePBB)})
	LayerTypeLwapp               = gopacket.RegisterLayerType(501, gopacket.LayerTypeMetadata{"Lwapp", gopacket.DecodeFunc(decodeLwapp)})
	LayerTypeLwappControl        = gopacket.RegisterLayerType(502, gopacket.LayerTypeMetadata{"LwappControl", gopacket.DecodeFunc(decodeLwappControl)})
	LayerTypeCapwapControl       = gopacket.RegisterLayerType(503, gopacket.LayerTypeMetadata{"CapwapControl", gopacket.DecodeFunc(decodeCapwapControl)})
	LayerTypeCapwapData          = gopacket.RegisterLayerType(504, gopacket.LayerTypeMetadata{"CapwapData", gopacket.DecodeFunc(decodeCapwapData)})
	LayerTypeCapwapControlHeader = gopacket.RegisterLayerType(505, gopacket.LayerTypeMetadata{"CapwapControlHeader", gopacket.DecodeFunc(decodeCapwapControlHeader)})
	LayerTypeCapwapDataKeepAlive = gopacket.RegisterLayerType(506, gopacket.LayerTypeMetadata{"CapwapDataKeepAlive", gopacket.DecodeFunc(decodeCapwapDataKeepAlive)})
	LayerTypeDot11NoFCS          = gopacket.RegisterLayerType(507, gopacket.LayerTypeMetadata{"Dot11NoFCS", gopacket.DecodeFunc(decodeDot11NoFCS)})
)

func decodeMPLS(data []byte, p gopacket.PacketBuilder) error {
	g := layers.ProtocolGuessingDecoder{}
	if err := g.Decode(data, p); err != nil {
		return gopacket.DecodePayload.Decode(data, p)
	}
	return nil
}

const (
	// 802.1QSTagType
	ethernetTypeDot1QSTag layers.EthernetType = 0x88a8
	// 802.1QITagType
	ethernetTypeDot1QITag layers.EthernetType = 0x88e7
	// LWAPP
	ethernetTypeLwapp layers.EthernetType = 0x88bb
)

type PBB struct {
	layers.BaseLayer
	Priority           uint8
	DropEligible       bool
	UseCustomerAddress bool
	ServiceIdentifier  uint32
	DstMAC             net.HardwareAddr
	SrcMAC             net.HardwareAddr
	Type               layers.EthernetType
}

func (p PBB) LayerType() gopacket.LayerType     { return LayerTypePBB }
func (p PBB) CanDecode() gopacket.LayerClass    { return LayerTypePBB }
func (p PBB) NextLayerType() gopacket.LayerType { return p.Type.LayerType() }
func (p PBB) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if bytes, err := b.PrependBytes(18); err != nil {
		return err
	} else {
		binary.BigEndian.PutUint32(bytes[0:4], p.ServiceIdentifier)
		firstByte := p.Priority << 5
		if p.DropEligible {
			firstByte |= 0x10
		}
		if p.UseCustomerAddress {
			firstByte |= 0x08
		}
		bytes[0] = firstByte

		for i, v := range []byte(p.DstMAC) {
			bytes[4+i] = v
		}
		for i, v := range []byte(p.SrcMAC) {
			bytes[10+i] = v
		}
		binary.BigEndian.PutUint16(bytes[16:18], uint16(p.Type))
	}
	return nil
}

func decodePBB(data []byte, p gopacket.PacketBuilder) error {
	if data[0]&0x3 != 0 {
		return errors.New("I-TAG TCI Res2 must be zero")
	}
	pbb := &PBB{
		Priority:           data[0] >> 5,
		DropEligible:       data[0]&0x10 != 0,
		UseCustomerAddress: data[0]&0x08 != 0,
		ServiceIdentifier:  binary.BigEndian.Uint32(append(make([]byte, 1), data[1:4]...)),
		DstMAC:             net.HardwareAddr(data[4:10]),
		SrcMAC:             net.HardwareAddr(data[10:16]),
		Type:               layers.EthernetType(binary.BigEndian.Uint16(data[16:18])),
		BaseLayer:          layers.BaseLayer{Contents: data[:18], Payload: data[18:]},
	}
	p.AddLayer(pbb)
	return p.NextDecoder(pbb.Type)
}

type LwappFlags uint8

func (self LwappFlags) Ver() uint8 {
	return uint8(self) >> 6
}

func (self LwappFlags) Rid() uint8 {
	return uint8(self&0x38) >> 3
}

// C bit indicates that the packet is message.
func (self LwappFlags) C() bool {
	return (self & 0x04) != 0
}

// F bit indicates that the packet is fragment.
func (self LwappFlags) F() bool {
	return (self & 0x02) != 0
}

// L bit indicates that the packet is NOT the last fragment.
func (self LwappFlags) L() bool {
	return (self & 0x01) != 0
}

// Lwapp Transport Header
type Lwapp struct {
	layers.BaseLayer
	Flags       LwappFlags
	FragID      uint8
	Length      uint16
	StatusWLANs uint16
}

// LayerType returns LayerTypeLwapp
func (self Lwapp) LayerType() gopacket.LayerType {
	return LayerTypeLwapp
}

func (self Lwapp) NextLayerType() gopacket.LayerType {
	if self.Flags.F() {
		return gopacket.LayerTypeFragment
	}
	if self.Flags.C() {
		return LayerTypeLwappControl
	}
	return LayerTypeDot11NoFCS
}

func decodeLwapp(data []byte, p gopacket.PacketBuilder) error {
	lwapp := &Lwapp{
		BaseLayer: layers.BaseLayer{
			Contents: data[:6],
			Payload:  data[6:],
		},
		Flags:       LwappFlags(data[0]),
		FragID:      data[1],
		Length:      binary.BigEndian.Uint16(data[2:]),
		StatusWLANs: binary.BigEndian.Uint16(data[4:]),
	}
	p.AddLayer(lwapp)
	return p.NextDecoder(lwapp.NextLayerType())
}

func (self Lwapp) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(6)
	if err != nil {
		return err
	}
	bytes[0] = uint8(self.Flags)
	bytes[1] = self.FragID
	binary.BigEndian.PutUint16(bytes[2:], uint16(len(self.Payload)))
	binary.BigEndian.PutUint16(bytes[4:], self.StatusWLANs)
	return nil
}

type LwappControl struct {
	layers.BaseLayer
	MessageType      uint8
	SeqNum           uint8
	MsgElementLength uint16
	SessionID        uint32
}

func (self LwappControl) LayerType() gopacket.LayerType {
	return LayerTypeLwappControl
}

func decodeLwappControl(data []byte, p gopacket.PacketBuilder) error {
	p.AddLayer(&LwappControl{
		BaseLayer: layers.BaseLayer{
			Contents: data[:8],
			Payload:  data[8:],
		},
		MessageType:      data[0],
		SeqNum:           data[1],
		MsgElementLength: binary.BigEndian.Uint16(data[2:]),
		SessionID:        binary.BigEndian.Uint32(data[4:]),
	})
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func (self LwappControl) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	bytes[0] = self.MessageType
	bytes[1] = self.SeqNum
	binary.BigEndian.PutUint16(bytes[2:], uint16(len(self.Payload)))
	binary.BigEndian.PutUint32(bytes[4:], self.SessionID)
	return nil
}

type CapwapPreamble uint32

func (self CapwapPreamble) Version() uint8 {
	return uint8(self >> 28)
}

func (self CapwapPreamble) Type() uint8 {
	return uint8(self>>24) & 0x0F
}

func (self CapwapPreamble) Hlen() uint8 {
	return uint8(self>>19) & 0x1F
}

func (self CapwapPreamble) Rid() uint8 {
	return uint8(self>>14) & 0x1F
}

func (self CapwapPreamble) Wbid() uint8 {
	return uint8(self>>9) & 0x1F
}

func (self CapwapPreamble) T() bool {
	return self&0x0100 != 0
}

func (self CapwapPreamble) F() bool {
	return self&0x80 != 0
}

func (self CapwapPreamble) L() bool {
	return self&0x40 != 0
}

func (self CapwapPreamble) W() bool {
	return self&0x20 != 0
}

func (self CapwapPreamble) M() bool {
	return self&0x10 != 0
}

func (self CapwapPreamble) K() bool {
	return self&0x08 != 0
}

func (self CapwapPreamble) Flags() uint8 {
	return uint8(self & 0x07)
}

type Capwap struct {
	layers.BaseLayer
	Preamble                    CapwapPreamble
	FragmentID                  uint16
	FragOffset                  uint16
	RadioMacAddress             []byte
	WirelessSpecificInformation []byte
}

func decodeCapwap(data []byte, p gopacket.PacketBuilder, isControl bool) error {
	preamble := CapwapPreamble(binary.BigEndian.Uint32(data[0:]))
	switch preamble.Type() {
	case 0:
		cw := Capwap{
			Preamble:   preamble,
			FragmentID: binary.BigEndian.Uint16(data[4:]),
			FragOffset: binary.BigEndian.Uint16(data[6:]) >> 3,
		}
		addLayer := func() {
			if isControl {
				p.AddLayer(&CapwapControl{
					Capwap: cw,
				})
			} else {
				p.AddLayer(&CapwapData{
					Capwap: cw,
				})
			}
		}
		if preamble.F() {
			addLayer()
			return p.NextDecoder(gopacket.LayerTypeFragment)
		}
		cur := 8
		if preamble.M() {
			maclen := int(data[cur])
			cw.RadioMacAddress = data[cur+1 : cur+1+maclen]
			cur += 1 + maclen
			cur = (cur + 3) / 4 * 4
		}
		if preamble.W() {
			switch data[cur] {
			case 1:
				// old draft spec IEEE 802.11
				length := int(data[cur+1])
				cw.WirelessSpecificInformation = data[cur+2 : cur+2+length]
				cur += 2 + length
				cur = (cur + 3) / 4 * 4
			case 4:
				cw.WirelessSpecificInformation = data[cur+1 : cur+5]
				cur += 5
				cur = (cur + 3) / 4 * 4
			default:
				return errors.New("unknown wireless specific information")
			}
		}
		cw.Contents = data[:cur]
		cw.Payload = data[cur:]
		addLayer()
		if isControl {
			return p.NextDecoder(LayerTypeCapwapControlHeader)
		} else if preamble.K() {
			// CAPWAP Data Channel Keep-Alive
			return p.NextDecoder(LayerTypeCapwapDataKeepAlive)
		} else {
			// payload format depends on WTP Frame Tunnel Mode element
			return p.NextDecoder(gopacket.LayerTypePayload)
		}
	case 1:
		// CAPWAP DTLS
		cw := Capwap{
			BaseLayer: layers.BaseLayer{
				Contents: data[:4],
				Payload:  data[4:],
			},
			Preamble: preamble,
		}
		if isControl {
			p.AddLayer(&CapwapControl{
				Capwap: cw,
			})
		} else {
			p.AddLayer(&CapwapData{
				Capwap: cw,
			})
		}
		return p.NextDecoder(gopacket.LayerTypePayload) // Payload is DTLS
	default:
		return p.NextDecoder(gopacket.LayerTypeDecodeFailure) // unknown
	}
}

type CapwapControl struct {
	Capwap
}

func (self CapwapControl) LayerType() gopacket.LayerType {
	return LayerTypeCapwapControl
}

func decodeCapwapControl(data []byte, p gopacket.PacketBuilder) error {
	return decodeCapwap(data, p, true)
}

type CapwapData struct {
	Capwap
}

func (self CapwapData) LayerType() gopacket.LayerType {
	return LayerTypeCapwapData
}

func decodeCapwapData(data []byte, p gopacket.PacketBuilder) error {
	return decodeCapwap(data, p, false)
}

type CapwapDataKeepAlive struct {
	layers.BaseLayer
	MessageElementLength uint16
}

func (self CapwapDataKeepAlive) LayerType() gopacket.LayerType {
	return LayerTypeCapwapDataKeepAlive
}

func decodeCapwapDataKeepAlive(data []byte, p gopacket.PacketBuilder) error {
	length := binary.BigEndian.Uint16(data)
	p.AddLayer(&CapwapDataKeepAlive{
		BaseLayer: layers.BaseLayer{
			Contents: data[:2],
			Payload:  data[2:length],
		},
		MessageElementLength: length,
	})
	return p.NextDecoder(gopacket.LayerTypePayload)
}

type CapwapControlHeader struct {
	layers.BaseLayer
	MessageType      uint32
	SeqNum           uint8
	MsgElementLength uint16
}

func (self CapwapControlHeader) LayerType() gopacket.LayerType {
	return LayerTypeCapwapControlHeader
}

func decodeCapwapControlHeader(data []byte, p gopacket.PacketBuilder) error {
	msgElementLength := binary.BigEndian.Uint16(data[5:])
	p.AddLayer(&CapwapControlHeader{
		BaseLayer: layers.BaseLayer{
			Contents: data[:8],
			Payload:  data[8 : 5+int(msgElementLength)],
		},
		MessageType:      binary.BigEndian.Uint32(data),
		SeqNum:           data[4],
		MsgElementLength: msgElementLength,
	})
	return p.NextDecoder(gopacket.LayerTypePayload)
}

type Dot11NoFCS struct {
	layers.BaseLayer
}

func (self Dot11NoFCS) LayerType() gopacket.LayerType {
	return LayerTypeDot11NoFCS
}

func (self Dot11NoFCS) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeDot11
}

func decodeDot11NoFCS(data []byte, p gopacket.PacketBuilder) error {
	payload := make([]byte, len(data)+4)
	copy(payload, data)
	h := crc32.NewIEEE()
	h.Write(data)
	binary.LittleEndian.PutUint32(payload[len(data):], h.Sum32())
	p.AddLayer(&Dot11NoFCS{
		BaseLayer: layers.BaseLayer{
			Payload: payload,
		},
	})
	return p.NextDecoder(layers.LayerTypeDot11)
}

func (self Dot11NoFCS) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	dot11 := append([]byte{}, b.Bytes()...)
	if err := b.Clear(); err != nil {
		return err
	}
	bytes, err := b.AppendBytes(len(dot11) - 4) // remove FCS
	if err != nil {
		return err
	}
	copy(bytes, dot11)
	return nil
}
