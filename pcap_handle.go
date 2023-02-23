package httpcapt

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type pcapHandle interface {
	gopacket.PacketDataSource
	SetBPFFilter(expr string) error
	LinkType() layers.LinkType
	Close()
}
