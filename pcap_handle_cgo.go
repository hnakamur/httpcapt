//go:build cgo

package httpcapt

import (
	"time"

	"github.com/google/gopacket/pcap"
)

var _ PcapHandle = (*cgoPcapHandle)(nil)

type cgoPcapHandle struct {
	*pcap.Handle
}

func openLivePcapHandle(device string, snaplen int32, promiscuous bool, timeout time.Duration) (PcapHandle, error) {
	if timeout == 0 {
		timeout = pcap.BlockForever
	}
	h, err := pcap.OpenLive(device, snaplen, promiscuous, timeout)
	if err != nil {
		return nil, err
	}
	return &cgoPcapHandle{Handle: h}, nil
}
