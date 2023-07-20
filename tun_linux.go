package libv2ray

import (
	"github.com/2dust/AndroidLibXrayLite/tun"
	"github.com/2dust/AndroidLibXrayLite/tun/gvisor"
	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func NewTun2ray(config *TunConfig) (*Tun2ray, error) {
	var endpoint stack.LinkEndpoint
	var err error
	endpoint, err = fdbased.New(&fdbased.Options{
		FDs: []int{int(config.FileDescriptor)},
		MTU: uint32(config.MTU),
	})
	if err != nil {
		return nil, err
	}

	tun2ray := &Tun2ray{
		vpoint:   config.V2Ray.Vpoint,
		udpTable: &natTable{},
		udpQueue: make(chan *tun.UDPPacket, 200),
		fakedns:  config.FakeDNS,
		sniffing: config.Sniffing,
	}
	tun2ray.stack, err = gvisor.New(endpoint, tun2ray, 0x01)
	if err != nil {
		return nil, err
	}

	for i := 0; i < numUDPWorkers(); i++ {
		go tun2ray.udpHandleUplink()
	}
	return tun2ray, nil
}
