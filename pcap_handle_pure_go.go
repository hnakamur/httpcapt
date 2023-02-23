//go:build linux && !cgo

package httpcapt

import (
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/packetcap/go-pcap/filter"
	"golang.org/x/net/bpf"
)

var _ PcapHandle = (*pureGoPcapHandle)(nil)

type pureGoPcapHandle struct {
	*pcapgo.EthernetHandle
}

func openLivePcapHandle(device string, snaplen int32, promiscuous bool, _ time.Duration) (PcapHandle, error) {
	h, err := pcapgo.NewEthernetHandle(device)
	if err != nil {
		return nil, err
	}
	h.SetCaptureLength(int(snaplen))
	h.SetPromiscuous(promiscuous)
	return &pureGoPcapHandle{EthernetHandle: h}, nil
}

func (h *pureGoPcapHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (h *pureGoPcapHandle) SetBPFFilter(expr string) error {
	e := filter.NewExpression(expr)
	insts, err := e.Compile().Compile()
	if err != nil {
		return err
	}
	rawInsts, err := bpf.Assemble(insts)
	if err != nil {
		return err
	}
	return h.EthernetHandle.SetBPF(rawInsts)
}
