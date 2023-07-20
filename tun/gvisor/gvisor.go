package gvisor

import (
	"errors"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"

	"github.com/2dust/AndroidLibXrayLite/tun"
)

func New(endpoint stack.LinkEndpoint, handler tun.Handler, nicId tcpip.NICID) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicId,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicId,
		},
	})

	bufSize := buf.Size
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})

	sOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)

	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)

	gTcpHandler(s, handler)
	gUdpHandler(s, handler)
	common.Must(tcpipErr(s.CreateNIC(nicId, endpoint)))
	common.Must(tcpipErr(s.SetSpoofing(nicId, true)))
	common.Must(tcpipErr(s.SetPromiscuousMode(nicId, true)))
	return s, nil
}

func tcpipErr(err tcpip.Error) error {
	if err != nil {
		return errors.New(err.String())
	}

	return nil
}
