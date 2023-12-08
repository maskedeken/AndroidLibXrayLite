package libv2ray

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	_ "unsafe"

	D "github.com/xtls/xray-core/app/dns"
	v2net "github.com/xtls/xray-core/common/net"
	v2dns "github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
	v2internet "github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

//go:linkname effectiveSystemDialer_ github.com/xtls/xray-core/transport/internet.effectiveSystemDialer
var effectiveSystemDialer_ internet.SystemDialer

var v2rayDefaultDialer *internet.DefaultSystemDialer

func init() {
	var ok bool
	v2rayDefaultDialer, ok = effectiveSystemDialer_.(*internet.DefaultSystemDialer)
	if !ok {
		panic("DefaultSystemDialer not found")
	}
}

type Func interface {
	Invoke() error
}

type ExchangeContext struct {
	context   context.Context
	addresses []net.IP
	error     error
}

func (c *ExchangeContext) OnCancel(callback Func) {
	go func() {
		<-c.context.Done()
		callback.Invoke()
	}()
}

func (c *ExchangeContext) Success(result []byte) {
	if len(result) == 0 {
		return
	}

	c.addresses, c.error = parseResponse(result)
}

func (c *ExchangeContext) ErrnoCode(code int32) {
	c.error = syscall.Errno(code)
}

// parseResponse parses DNS answers from the returned payload
func parseResponse(payload []byte) ([]net.IP, error) {
	var parser dnsmessage.Parser
	_, err := parser.Start(payload)
	if err != nil {
		return nil, err
	}
	if err = parser.SkipAllQuestions(); err != nil {
		return nil, err
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return nil, err
	}

	var addresses []net.IP
	for _, res := range answers {
		switch res.Header.Type {
		case dnsmessage.TypeA:
			ans := res.Body.(*dnsmessage.AResource)
			addresses = append(addresses, ans.A[:])
		case dnsmessage.TypeAAAA:
			ans := res.Body.(*dnsmessage.AAAAResource)
			addresses = append(addresses, ans.AAAA[:])
		}
	}

	return addresses, nil
}

type protectSet interface {
	Protect(int) bool
	GetResolver() UnderlyingResolver
}

// NewPreotectedDialer ...
func NewPreotectedDialer(p protectSet) *ProtectedDialer {
	d := &ProtectedDialer{
		// prefer native lookup on Android
		resolver:   &net.Resolver{PreferGo: false},
		protectSet: p,
	}
	return d
}

// ProtectedDialer ...
type ProtectedDialer struct {
	currentServer string
	preferIPv6    bool
	resolver      *net.Resolver
	reqID         uint32

	protectSet
}

func (d *ProtectedDialer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&d.reqID, 1))
}

func (d *ProtectedDialer) lookupAddr(network string, domain string) (IPs []net.IP, err error) {
	underlyingResolver := d.GetResolver()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ok := make(chan interface{})
	defer cancel()

	go func() {
		defer func() {
			select {
			case <-ctx.Done():
			default:
				ok <- nil
			}
			close(ok)
		}()

		if underlyingResolver != nil {
			switch network {
			case "ip4":
				IPs, err = d.exchange(ctx, underlyingResolver, domain, dnsmessage.TypeA)
			case "ip6":
				IPs, err = d.exchange(ctx, underlyingResolver, domain, dnsmessage.TypeAAAA)
			case "ip":
				ip6Ch := make(chan []net.IP, 1)
				go func() { // query IPv6 address
					defer close(ip6Ch)

					ip6, err := d.exchange(ctx, underlyingResolver, domain, dnsmessage.TypeAAAA)
					if err != nil {
						return
					}

					ip6Ch <- ip6
				}()

				ip4, err2 := d.exchange(ctx, underlyingResolver, domain, dnsmessage.TypeA)
				if err2 == nil {
					IPs = append(IPs, ip4...)
				}

				if ip6, ok := <-ip6Ch; ok {
					IPs = append(IPs, ip6...)
				}
			default:
				err = net.UnknownNetworkError(network)
			}
		} else {
			IPs, err = d.resolver.LookupIP(ctx, network, domain)
		}

		if err == nil && len(IPs) == 0 {
			err = dns.ErrEmptyResponse
		}
	}()

	select {
	case <-ctx.Done():
		return nil, errors.New("underlyingResolver: context cancelled")
	case <-ok:
	}

	if err == nil && network == "ip" {
		IPs = reorderAddresses(IPs, d.preferIPv6)
	}

	return
}

func (d *ProtectedDialer) exchange(ctx context.Context, resolver UnderlyingResolver, domain string, nsType dnsmessage.Type) ([]net.IP, error) {
	fqdn := D.Fqdn(domain)
	query := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(fqdn),
		Type:  nsType,
		Class: dnsmessage.ClassINET,
	}
	msg := new(dnsmessage.Message)
	msg.Header.ID = d.newReqID()
	msg.Header.RecursionDesired = true
	msg.Questions = []dnsmessage.Question{query}
	b, err := v2dns.PackMessage(msg)
	if err != nil {
		return nil, err
	}

	response := &ExchangeContext{
		context: ctx,
	}
	err = resolver.Exchange(response, b.Bytes())
	if err != nil {
		return nil, err
	}
	return response.addresses, response.error
}

func (d *ProtectedDialer) getFd(network v2net.Network) (fd int, err error) {
	switch network {
	case v2net.Network_TCP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	case v2net.Network_UDP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	default:
		err = errors.New("unknow network")
	}
	return
}

// Init implement internet.SystemDialer
func (d *ProtectedDialer) Init(_ dns.Client, _ outbound.Manager) {
	// do nothing
}

// Dial exported as the protected dial method
func (d *ProtectedDialer) Dial(ctx context.Context,
	src v2net.Address, dest v2net.Destination, sockopt *v2internet.SocketConfig) (conn net.Conn, err error) {
	var ip net.IP
	if dest.Address.Family().IsIP() {
		ip = dest.Address.IP()
		if ip.IsLoopback() { // is it more effective
			return v2rayDefaultDialer.Dial(ctx, src, dest, sockopt)
		}
		return d.fdConn(ctx, dest, sockopt)
	}

	ob := session.OutboundFromContext(ctx)
	if ob == nil {
		return nil, errors.New("outbound is not specified")
	}

	r := ob.Resolved
	if r == nil {
		var ips []net.IP
		haveV4 := d.haveIPv4()
		haveV6 := d.haveIPv6()
		network := "ip"
		if haveV4 && !haveV6 {
			network = "ip4"
		} else if !haveV4 && haveV6 {
			network = "ip6"
		}
		ips, err = d.lookupAddr(network, dest.Address.Domain())
		if err != nil {
			return nil, err
		}

		r = &session.Resolved{
			IPs: ips,
		}
		ob.Resolved = r
	}

	ip = r.CurrentIP()
	if ip == nil {
		return nil, errors.New("no IP specified")
	}

	dest2 := dest
	dest2.Address = v2net.IPAddress(ip)
	conn, err = d.fdConn(ctx, dest2, sockopt)
	if err != nil {
		r.NextIP()
		return nil, err
	}

	return conn, err
}

/**
 * Check if given network has Ipv4 capability
 * This function matches the behaviour of have_ipv4 in the native resolver.
 */
func (d *ProtectedDialer) haveIPv4() bool {
	return d.checkConnectivity(TEST_DESTINATION_IPV4)
}

/**
 * Check if given network has Ipv6 capability
 * This function matches the behaviour of have_ipv6 in the native resolver.
 */
func (d *ProtectedDialer) haveIPv6() bool {
	return d.checkConnectivity(TEST_DESTINATION_IPV6)
}

func (d *ProtectedDialer) checkConnectivity(dest v2net.Destination) bool {
	fd, err := d.getFd(dest.Network)
	if err != nil {
		log.Printf("checkConnectivity: fail to open socket, Err: %v", err)
		return false
	}
	defer unix.Close(fd)

	if !d.Protect(fd) {
		log.Printf("checkConnectivity: fail to protect, Close Fd: %d", fd)
		return false
	}

	sa := &unix.SockaddrInet6{
		Port: int(dest.Port.Value()),
	}
	copy(sa.Addr[:], dest.Address.IP().To16())
	return unix.Connect(fd, sa) == nil
}

func (d *ProtectedDialer) fdConn(ctx context.Context, dest v2net.Destination, sockopt *v2internet.SocketConfig) (net.Conn, error) {
	fd, err := d.getFd(dest.Network)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	// call android VPN service to "protect" the fd connecting straight out
	if !d.Protect(fd) {
		log.Printf("fdConn fail to protect, Close Fd: %d", fd)
		return nil, errors.New("fail to protect")
	}

	// Apply sockopt
	if sockopt != nil {
		internet.ApplySockopt(ctx, dest, uintptr(fd), sockopt)
	}

	sa := &unix.SockaddrInet6{
		Port: int(dest.Port.Value()),
	}
	copy(sa.Addr[:], dest.Address.IP().To16())

	if err := unix.Connect(fd, sa); err != nil {
		log.Printf("fdConn unix.Connect err, Close Fd: %d Err: %v", fd, err)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "Socket")
	if file == nil {
		// returned value will be nil if fd is not a valid file descriptor
		return nil, errors.New("fdConn fd invalid")
	}

	defer file.Close()
	//Closing conn does not affect file, and closing file does not affect conn.
	conn, err := net.FileConn(file)
	if err != nil {
		log.Printf("fdConn FileConn Close Fd: %d Err: %v", fd, err)
		return nil, err
	}

	return conn, nil
}

func reorderAddresses(ips []net.IP, preferIPv6 bool) []net.IP {
	var result []net.IP
	for i := 0; i < 2; i++ {
		for _, ip := range ips {
			if (preferIPv6 == (i == 0)) == (ip.To4() == nil) {
				result = append(result, ip)
			}
		}
	}
	return result
}
