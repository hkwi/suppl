package syscall

const (
	IFF_LOWER_UP = 1 << 16
	IFF_DORMANT  = 1 << 17
)

const (
	ARPHRD_6LOWPAN = 825
)

// htons(syscall.ETH_P_ALL)
const ETH_P_ALL uint16 = 0x0300

type Auxdata struct {
	Status   uint32
	Len      uint32
	Snaplen  uint32
	Mac      uint16
	Net      uint16
	VlanTci  uint16
	VlanTpid uint16
}

const (
	PACKET_AUXDATA = 8
	PACKET_VERSION = 10
)
const (
	TPACKET_V1 = iota
	TPACKET_V2
	TPACKET_V3
)
const (
	TP_STATUS_VLAN_VALID      = 1 << 4
	TP_STATUS_VLAN_TPID_VALID = 1 << 6
)
