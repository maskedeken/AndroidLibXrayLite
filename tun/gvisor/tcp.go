package gvisor

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/2dust/AndroidLibXrayLite/tun"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/waiter"
	v2rayNet "github.com/xtls/xray-core/common/net"
)

func gTcpHandler(s *stack.Stack, handler tun.Handler) {
	forwarder := tcp.NewForwarder(s, 0, 1024, func(request *tcp.ForwarderRequest) {
		id := request.ID()
		waitQueue := new(waiter.Queue)
		endpoint, errT := request.CreateEndpoint(waitQueue)
		if errT != nil {
			log.Printf("failed to create TCP connection, Err: %v", errT)
			// prevent potential half-open TCP connection leak.
			request.Complete(true)
			return
		}
		request.Complete(false)
		srcAddr := net.JoinHostPort(id.RemoteAddress.String(), strconv.Itoa(int(id.RemotePort)))
		src, err := v2rayNet.ParseDestination(fmt.Sprint("tcp:", srcAddr))
		if err != nil {
			log.Printf("[TCP] parse source address %s, Err: %v", srcAddr, err)
			return
		}
		dstAddr := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		dst, err := v2rayNet.ParseDestination(fmt.Sprint("tcp:", dstAddr))
		if err != nil {
			log.Printf("[TCP] parse destination address %s, Err: %v", dstAddr, err)
			return
		}
		go handler.NewConnection(src, dst, gTcpConn{endpoint, gonet.NewTCPConn(waitQueue, endpoint)})
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
}

type gTcpConn struct {
	ep tcpip.Endpoint
	*gonet.TCPConn
}

func (g gTcpConn) Close() error {
	g.ep.Close()
	g.TCPConn.SetDeadline(time.Now().Add(-1))
	return g.TCPConn.Close()
}
