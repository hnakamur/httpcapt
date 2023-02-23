package httpcapt

import (
	"context"
	"net/http"
	"net/netip"
	"time"
)

type CaptureResult struct {
	RequestTime time.Time
	Time        time.Time
	Client      netip.AddrPort
	Server      netip.AddrPort
	Response    *http.Response
	Error       error
}

type Capturer interface {
	SetBPFFilter(expr string) error
	Capture(ctx context.Context, resultC chan<- CaptureResult)
}

// NewEthernetCapturer creates a Capturer which captures packets for
// the device Ethernet device specified.
//
// If device is "any", a captuerer for all devices on the host is returned.
func NewEthernetCapturer(device string) (Capturer, error) {
	return newEthernetCapturer(device)
}

type singleDeviceCapturer struct {
	handle pcapHandle
}

func newSingleDeviceCapturer(device string) (*singleDeviceCapturer, error) {
	h, err := openEthernetHandle(device)
	if err != nil {
		return nil, err
	}
	return &singleDeviceCapturer{handle: h}, nil
}

func (c *singleDeviceCapturer) SetBPFFilter(expr string) error {
	return c.handle.SetBPFFilter(expr)
}

func (c *singleDeviceCapturer) Capture(ctx context.Context, resultC chan<- CaptureResult) {
	streamFactory := newHTTPStreamFactory(c.handle, resultC)
	err := streamFactory.Run(ctx)
	if err != nil {
		resultC <- CaptureResult{Error: err}
	}
	c.handle.Close()
}

func NewMultiEthernetCapturer(devices []string) (Capturer, error) {
	capturers := make([]*singleDeviceCapturer, len(devices))
	for i, dev := range devices {
		capturer, err := newSingleDeviceCapturer(dev)
		if err != nil {
			return nil, err
		}
		capturers[i] = capturer
	}
	return &multiDevicesCapturer{capturers: capturers}, nil
}

type multiDevicesCapturer struct {
	capturers []*singleDeviceCapturer
}

func (c *multiDevicesCapturer) SetBPFFilter(expr string) error {
	for _, capturer := range c.capturers {
		if err := capturer.SetBPFFilter(expr); err != nil {
			return err
		}
	}
	return nil
}

func (c *multiDevicesCapturer) Capture(ctx context.Context, resultC chan<- CaptureResult) {
	for _, capturer := range c.capturers {
		go capturer.Capture(ctx, resultC)
	}
}
