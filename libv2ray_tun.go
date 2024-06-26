package libv2ray

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"syscall"
	"time"

	singtun "github.com/sagernet/sing-tun"
	singcom "github.com/sagernet/sing/common"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type TunConfig struct {
	FileDescriptor int32
	MTU            int32
	V2Ray          *V2RayPoint
	Implementation int32
	Sniffing       bool
	FakeDNS        bool
	RouteOnly      bool
}

type V2Tun struct {
	vpoint *core.Instance
	dev    singtun.Tun
	stack  singtun.Stack

	fakedns   bool
	sniffing  bool
	routeOnly bool
}

func NewV2Tun(config *TunConfig) (*V2Tun, error) {
	tunFd, err := syscall.Dup(int(config.FileDescriptor))
	if err != nil {
		return nil, fmt.Errorf("syscall.Dup: %v", err)
	}

	var addr4, addr6 []netip.Prefix
	prefix4, _ := netip.ParsePrefix(PRIVATE_VLAN4_CLIENT + "/30")
	addr4 = append(addr4, prefix4)
	if config.V2Ray.dialer.preferIPv6 {
		prefix6, _ := netip.ParsePrefix(PRIVATE_VLAN6_CLIENT + "/126")
		addr6 = append(addr6, prefix6)
	}

	dev, err := singtun.New(singtun.Options{
		FileDescriptor: tunFd,
		MTU:            uint32(config.MTU),
		Inet4Address:   addr4,
		Inet6Address:   addr6,
	})
	if err != nil {
		return nil, err
	}

	var stack string
	switch config.Implementation {
	case 2:
		stack = "mixed"
	case 1:
		stack = "system"
	default:
		stack = "gvisor"
	}

	v2tun := &V2Tun{
		vpoint:    config.V2Ray.Vpoint,
		dev:       dev,
		fakedns:   config.FakeDNS,
		sniffing:  config.Sniffing,
		routeOnly: config.RouteOnly,
	}
	v2tun.stack, err = singtun.NewStack(stack, singtun.StackOptions{
		Context: context.Background(),
		Tun:     dev,
		TunOptions: singtun.Options{
			Name:         "v2tun",
			MTU:          uint32(config.MTU),
			Inet4Address: addr4,
			Inet6Address: addr6,
		},
		UDPTimeout: 30,
		Handler:    v2tun,
		Logger:     logger.NOP(),
	})
	if err != nil {
		dev.Close()
		return nil, err
	}

	err = v2tun.stack.Start()
	if err != nil {
		dev.Close()
		return nil, err
	}

	return v2tun, nil
}

func (t *V2Tun) Close() error {
	return singcom.Close(t.stack, t.dev)
}

func (t *V2Tun) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	source := singbridge.ToDestination(metadata.Source, v2net.Network_TCP)
	destination := singbridge.ToDestination(metadata.Destination, v2net.Network_TCP)
	dispatcher := t.vpoint.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	ctx = core.WithContext(ctx, t.vpoint)
	inbound := &session.Inbound{
		Source: source,
		Conn:   conn,
	}
	inbound.CanSpliceCopy = 2
	ctx = session.ContextWithInbound(ctx, inbound)

	// [TCP] dns to router
	isDns := (destination.Address.String() == PRIVATE_VLAN4_ROUTER || destination.Address.String() == LOCALHOST) && destination.Port.Value() == 53
	if isDns {
		inbound.Name = "dokodemo-door"
		inbound.Tag = "dns-in"
		ctx = session.SetForcedOutboundTagToContext(ctx, "dns-out")
	} else {
		inbound.Name = "socks"
		inbound.Tag = "socks"
	}

	// [tun-in] [TCP] sniffing
	if !isDns && (t.sniffing || t.fakedns) {
		req := session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: t.fakedns && !t.sniffing,
			RouteOnly:    !t.sniffing || t.routeOnly,
		}
		if t.sniffing && t.fakedns {
			req.OverrideDestinationForProtocol = []string{"fakedns", "http", "tls"}
		}
		if t.sniffing && !t.fakedns {
			req.OverrideDestinationForProtocol = []string{"http", "tls"}
		}
		if !t.sniffing && t.fakedns {
			req.OverrideDestinationForProtocol = []string{"fakedns"}
		}
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: req,
		})
	}

	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return err
	}

	serverConn := &linkConn{
		link: link,
	}
	return bufio.CopyConn(ctx, conn, serverConn)
}

func (t *V2Tun) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	source := singbridge.ToDestination(metadata.Source, v2net.Network_UDP)
	destination := singbridge.ToDestination(metadata.Destination, v2net.Network_UDP)
	inbound := &session.Inbound{
		Source: source,
	}
	ctx = session.ContextWithInbound(ctx, inbound)

	// [UDP] dns to router
	if destination.Address.String() == PRIVATE_VLAN4_ROUTER {
		inbound.Name = "dokodemo-door"
		inbound.Tag = "dns-in"
		ctx = session.SetForcedOutboundTagToContext(ctx, "dns-out")
	} else {
		inbound.Name = "socks"
		inbound.Tag = "socks"

		// [UDP] sniffing
		override := []string{}
		if t.fakedns {
			override = append(override, "fakedns")
		}
		if t.sniffing {
			override = append(override, "quic")
		}
		if len(override) != 0 {
			ctx = session.ContextWithContent(ctx, &session.Content{
				SniffingRequest: session.SniffingRequest{
					Enabled:                        true,
					MetadataOnly:                   t.fakedns && !t.sniffing,
					OverrideDestinationForProtocol: override,
					RouteOnly:                      !t.sniffing || t.routeOnly,
				},
			})
		}
	}

	dispatcher := t.vpoint.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	ctx = core.WithContext(ctx, t.vpoint)
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return err
	}

	serverConn := &linkPacketConn{
		dest: destination,
		link: link,
		fake: FAKEDNS_VLAN4_CLIENT_IPNET.Contains(destination.Address.IP()) || FAKEDNS_VLAN6_CLIENT_IPNET.Contains(destination.Address.IP()),
	}
	return bufio.CopyPacketConn(ctx, conn, serverConn)
}

func (t *V2Tun) NewError(ctx context.Context, err error) {
	log.Printf("Err: %s\n", err.Error())
}

type linkConn struct {
	link   *transport.Link
	cached buf.MultiBuffer
}

func (c *linkConn) Read(p []byte) (int, error) {
	if len(c.cached) > 0 {
		mb, totalBytes := buf.SplitBytes(c.cached, p)
		c.cached = mb
		if totalBytes > 0 {
			return totalBytes, nil
		}
	}

	mb, err := c.link.Reader.ReadMultiBuffer()
	if err != nil {
		return 0, err
	}

	nb, totalBytes := buf.SplitBytes(mb, p)
	c.cached = nb
	return totalBytes, nil
}

func (c *linkConn) Write(p []byte) (n int, err error) {
	n = len(p)
	var mb buf.MultiBuffer
	pLen := len(p)
	for pLen > 0 {
		buffer := buf.New()
		if pLen > buf.Size {
			_, err = buffer.Write(p[:buf.Size])
			p = p[buf.Size:]
		} else {
			buffer.Write(p)
		}
		pLen -= int(buffer.Len())
		mb = append(mb, buffer)
	}
	err = c.link.Writer.WriteMultiBuffer(mb)
	if err != nil {
		n = 0
		buf.ReleaseMulti(mb)
	}
	return
}

func (c *linkConn) Close() error {
	_ = common.Interrupt(c.link.Reader)
	_ = common.Interrupt(c.link.Writer)
	return nil
}

func (*linkConn) LocalAddr() net.Addr {
	return nil
}

func (*linkConn) RemoteAddr() net.Addr {
	return nil
}

func (*linkConn) SetDeadline(t time.Time) error {
	return nil
}

func (*linkConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (*linkConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type linkPacketConn struct {
	dest   v2net.Destination
	link   *transport.Link
	fake   bool // fakedns 198.18.x.x
	cached buf.MultiBuffer
}

func (c *linkPacketConn) ReadPacket(buffer *B.Buffer) (M.Socksaddr, error) {
	if c.cached != nil {
		mb, bb := buf.SplitFirst(c.cached)
		if bb == nil {
			c.cached = nil
		} else {
			buffer.Write(bb.Bytes())
			c.cached = mb
			var src v2net.Destination
			if c.fake {
				src = c.dest
			} else {
				if bb.UDP == nil {
					src = c.dest
				} else {
					src = *bb.UDP
				}
			}
			bb.Release()
			return singbridge.ToSocksaddr(src), nil
		}
	}

	mb, err := c.link.Reader.ReadMultiBuffer()
	if err != nil {
		return M.Socksaddr{}, err
	}
	nb, bb := buf.SplitFirst(mb)
	if bb == nil {
		return M.Socksaddr{}, nil
	} else {
		buffer.Write(bb.Bytes())
		c.cached = nb
		var src v2net.Destination
		if c.fake {
			src = c.dest
		} else {
			if bb.UDP == nil {
				src = c.dest
			} else {
				src = *bb.UDP
			}
		}
		bb.Release()
		return singbridge.ToSocksaddr(src), nil
	}
}

func (c *linkPacketConn) WritePacket(buffer *B.Buffer, destination M.Socksaddr) error {
	vBuf := buf.New()
	vBuf.Write(buffer.Bytes())
	if !c.fake {
		endpoint := singbridge.ToDestination(destination, v2net.Network_UDP)
		vBuf.UDP = &endpoint
	}
	return c.link.Writer.WriteMultiBuffer(buf.MultiBuffer{vBuf})
}

func (c *linkPacketConn) Close() error {
	_ = common.Interrupt(c.link.Reader)
	_ = common.Interrupt(c.link.Writer)
	return nil
}

func (c *linkPacketConn) LocalAddr() net.Addr {
	return nil
}

func (c *linkPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *linkPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *linkPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}
