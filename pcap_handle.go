package httpcapt

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PcapHandle interface {
	gopacket.PacketDataSource
	SetBPFFilter(expr string) error
	LinkType() layers.LinkType
	Close()
}

func OpenLivePcapHandle(device string, snaplen int32, promiscuous bool, timeout time.Duration) (PcapHandle, error) {
	return openLivePcapHandle(device, snaplen, promiscuous, timeout)
}
