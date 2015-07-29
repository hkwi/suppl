package syscall

const (
	BRPROTO_L2CAP = iota
	BRPROTO_HCI
	BRPROTO_SCO
	BRPROTO_RFCOMM
	BRPROTO_BNEP
	BRPROTO_CMTP
	BRPROTO_HIDP
	BRPROTO_AVDTP
)

type HciDevReq struct {
	DevId uint16
	DevOpt uint32
}

type HciDevListReq struct {
	DevNum uint16
	DevReq []HciDevReq
}
