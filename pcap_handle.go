package httpcapt

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PcapHandle interface {
	gopacket.PacketDataSource
	SetBPFFilter(expr string) error
	LinkType() layers.LinkType
	Close()
}

func OpenEthernetHandle(device string) (PcapHandle, error) {
	return openEthernetHandle(device)
}
