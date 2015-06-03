package layers

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"testing"
)

func TestLwapp(t *testing.T) {
	pkt := []byte{
		1, 2, 3, 4, 5, 6,
		1, 2, 3, 4, 5, 6,
		0x88, 0xbb,
		0,    // lwapp.flags
		0,    // lwapp.fragId
		0, 0, // lwapp.ength
		0, 0, // lwapp.statusWLANs
		0x0c, 0x00, 0, 0, // reserved
		9, 8, 7, 6, 5, 4,
		9, 8, 7, 6, 5, 4}
	p := gopacket.NewPacket(pkt, layers.LinkTypeEthernet, gopacket.Default)

	dot11 := p.Layer(layers.LayerTypeDot11).(*layers.Dot11)
	if !bytes.Equal(dot11.Address1, []byte{9, 8, 7, 6, 5, 4}) {
		t.Error("dot11 addr1 error")
	}
}

// No serialization test because layers.Dot11 does not implement SerializeTo
