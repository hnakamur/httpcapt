//go:build linux && !cgo

package httpcapt

import (
	"time"

	"github.com/google/gopacket/layers"
	"github.com/packetcap/go-pcap"
)

var _ PcapHandle = (*pureGoPcapHandle)(nil)

type pureGoPcapHandle struct {
	*pcap.Handle
}

func openLivePcapHandle(device string, snaplen int32, promiscuous bool, timeout time.Duration) (PcapHandle, error) {
	h, err := pcap.OpenLive(device, snaplen, promiscuous, timeout, false)
	if err != nil {
		return nil, err
	}
	return &pureGoPcapHandle{Handle: h}, nil
}

func (h *pureGoPcapHandle) LinkType() layers.LinkType {
	return layers.LinkType(h.Handle.LinkType())
}
