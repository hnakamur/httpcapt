# httpcapt

a HTTP/1.1 packet capture library written in Go.

For cgo enabled build, `libpcap` is needed. On Ubuntu/Debian, run the following command to install `libpcap-dev`.

```
sudo apt-get install -y libpcap-dev
```

On Linux, pure go build is also possible with `CGO_ENABLED=0 go build`

## Example

Please see [cmd/httpcapt/main.go](https://github.com/hnakamur/httpcapt/blob/main/cmd/httpcapt/main.go) for example usage.

## Credits

This library uses [github.com/google/gopacket/pcap](https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap) for cgo build,
[github.com/google/gopacket/pcapgo](https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcapgo) and 
[github.com/packetcap/go-pcap/filter](https://pkg.go.dev/github.com/packetcap/go-pcap@v0.0.0-20221020071412-2b2e94010282/filter) for pure go build.
Thanks for useful libraries!
