package libv2ray

import (
	"context"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/2dust/AndroidLibXrayLite/tun"
	"github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	v2rayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
)

var _ tun.Tun = (*Tun2ray)(nil)
var _ tun.Handler = (*Tun2ray)(nil)

type TunConfig struct {
	FileDescriptor int32
	MTU            int32
	V2Ray          *V2RayPoint
	Sniffing       bool
	FakeDNS        bool
}

type Tun2ray struct {
	v2rayPoint *V2RayPoint
	stack      *stack.Stack

	udpTable *natTable
	udpQueue chan *tun.UDPPacket

	fakedns  bool
	sniffing bool
}

func (t *Tun2ray) Close() {
	defer close(t.udpQueue)
	if t.stack != nil {
		t.stack.Close()
	}
}

func (t *Tun2ray) NewConnection(source v2rayNet.Destination, destination v2rayNet.Destination, conn net.Conn) {
	t.v2rayPoint.v2rayOP.Lock()
	if !t.v2rayPoint.IsRunning {
		conn.Close()
		t.v2rayPoint.v2rayOP.Unlock()
		return
	}
	v := t.v2rayPoint.Vpoint
	t.v2rayPoint.v2rayOP.Unlock()

	ctx := core.WithContext(context.Background(), v)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: source,
	})

	// [TCP] dns to router
	isDns := destination.Address.String() == tun.PRIVATE_VLAN4_ROUTER && destination.Port.Value() == 53
	if isDns {
		ctx = session.SetForcedOutboundTagToContext(ctx, "dns-out")
	}

	// [tun-in] [TCP] sniffing
	if !isDns && (t.sniffing || t.fakedns) {
		req := session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: t.fakedns && !t.sniffing,
			RouteOnly:    true,
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

	//这个 DispatchLink 是 outbound, link reader 是上行流量
	rw := &connReaderWriter{conn, buf.NewReader(conn), buf.NewWriter(conn)}
	link := &transport.Link{
		Reader: rw,
		Writer: rw,
	}
	err := t.v2rayPoint.dispatcher.DispatchLink(ctx, destination, link)

	if err != nil {
		log.Printf("[TCP] dispatchLink failed: %s", err.Error())
		closeIgnore(link.Reader, link.Writer)
		closeIgnore(conn)
		return
	}
}

// UDP

func (t *Tun2ray) HandlePacket(p *tun.UDPPacket) {
	t.udpQueue <- p
}

func (t *Tun2ray) udpHandleUplink() {
	for p := range t.udpQueue {
		t.udpHandleUplinkInternal(p)
	}
}

func (t *Tun2ray) udpHandleUplinkInternal(p *tun.UDPPacket) {
	natKey := p.Src.String()

	sendTo := func() bool {
		conn := t.udpTable.Get(natKey)
		if conn == nil {
			return false
		}
		_, err := conn.WriteTo(p.Data, p.Dst)
		if err != nil {
			_ = conn.Close()
		}
		return true
	}

	// cached udp conn
	if sendTo() {
		return
	}

	// new udp conn
	lockKey := natKey + "-lock"
	cond, loaded := t.udpTable.GetOrCreateLock(lockKey)

	// cached udp conn (waiting)
	if loaded {
		cond.L.Lock()
		cond.Wait()
		sendTo()
		cond.L.Unlock()
		return
	}

	// new udp conn
	source := v2rayNet.DestinationFromAddr(p.Src)
	destination := v2rayNet.DestinationFromAddr(p.Dst)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: source,
	})

	// change destination
	destination2 := destination

	// [UDP] dns to router
	isDns := destination.Address.String() == tun.PRIVATE_VLAN4_ROUTER

	// [UDP] dns to all
	dnsMsg := dns.Msg{}
	err := dnsMsg.Unpack(p.Data)
	if err == nil && !dnsMsg.Response && len(dnsMsg.Question) > 0 {
		// v2ray only support A and AAAA
		switch dnsMsg.Question[0].Qtype {
		case dns.TypeA:
			isDns = true
		case dns.TypeAAAA:
			isDns = true
		default:
			if isDns {
				// unknown dns traffic send as UDP to 8.8.8.8
				destination2.Address = v2rayNet.ParseAddress("8.8.8.8")
			}
			isDns = false
		}
	}

	if isDns {
		ctx = session.SetForcedOutboundTagToContext(ctx, "dns-out")
	}

	// [tun-in] [UDP] sniffing
	if !isDns {
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
					RouteOnly:                      true,
				},
			})
		}
	}

	workerN := 1
	timeout := time.Minute
	if !isDns {
		workerN = numUDPWorkers()
	} else {
		timeout = time.Second * 30
	}

	t.v2rayPoint.v2rayOP.Lock()
	if !t.v2rayPoint.IsRunning {
		t.v2rayPoint.v2rayOP.Unlock()
		return
	}
	v := t.v2rayPoint.Vpoint
	t.v2rayPoint.v2rayOP.Unlock()

	ctx = core.WithContext(ctx, v)
	conn, err := t.v2rayPoint.newDispatcherConn(ctx, destination, destination2, p.WriteBack, timeout, workerN)
	if err != nil {
		log.Printf("[UDP] dial failed: %s", err.Error())
		return
	}

	// [FakeDNS] [UDP] must fake ip & no endpoint change
	if tun.FAKEDNS_VLAN4_CLIENT_IPNET.Contains(destination.Address.IP()) {
		conn.fake = true
	}

	// udp conn ok
	t.udpTable.Set(natKey, conn)
	t.udpTable.Delete(lockKey)
	cond.Broadcast()

	// uplink
	sendTo()

	// wait for connection ends
	go func() {
		// downlink (moved to handleDownlink)
		<-conn.ctx.Done()

		// close
		closeIgnore(conn)
		t.udpTable.Delete(natKey)
	}()
}

type connReaderWriter struct {
	net.Conn
	buf.Reader
	buf.Writer
}

func (r *connReaderWriter) ReadMultiBufferTimeout(t time.Duration) (buf.MultiBuffer, error) {
	r.SetReadDeadline(time.Now().Add(t))
	defer r.SetReadDeadline(time.Time{})
	mb, err := r.ReadMultiBuffer()
	if err != nil {
		if nerr, ok := errors.Cause(err).(net.Error); ok && nerr.Timeout() {
			return nil, buf.ErrReadTimeout
		}
		return nil, err
	}
	return mb, nil
}

func (r *connReaderWriter) Interrupt() {
	r.Close()
}

func (r *connReaderWriter) Close() (err error) {
	return r.Conn.Close()
}

type natTable struct {
	mapping sync.Map
}

func (t *natTable) Set(key string, pc *dispatcherConn) {
	t.mapping.Store(key, pc)
}

func (t *natTable) Get(key string) *dispatcherConn {
	item, exist := t.mapping.Load(key)
	if !exist {
		return nil
	}
	return item.(*dispatcherConn)
}

func (t *natTable) GetOrCreateLock(key string) (*sync.Cond, bool) {
	item, loaded := t.mapping.LoadOrStore(key, sync.NewCond(&sync.Mutex{}))
	return item.(*sync.Cond), loaded
}

func (t *natTable) Delete(key string) {
	t.mapping.Delete(key)
}

func closeIgnore(closer ...interface{}) {
	for _, c := range closer {
		if c == nil {
			continue
		}
		if ia, ok := c.(common.Interruptible); ok {
			ia.Interrupt()
		} else if ca, ok := c.(common.Closable); ok {
			_ = ca.Close()
		}
	}
}

func numUDPWorkers() int {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}
	return numUDPWorkers
}
