//go:build cgo

package httpcapt

func newEthernetCapturer(device string) (Capturer, error) {
	return newSingleDeviceCapturer(device)
}
