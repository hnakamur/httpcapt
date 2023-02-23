//go:build linux && !cgo

package httpcapt

import (
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/packetcap/go-pcap/filter"
	"golang.org/x/net/bpf"
)

var _ pcapHandle = (*pureGoPcapHandle)(nil)

type pureGoPcapHandle struct {
	*pcapgo.EthernetHandle
}

func openEthernetHandle(device string) (pcapHandle, error) {
	h, err := pcapgo.NewEthernetHandle(device)
	if err != nil {
		return nil, err
	}
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
