package libv2ray

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	_ "unsafe"

	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
	v2internet "github.com/xtls/xray-core/transport/internet"
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

	protectSet
}

func (d *ProtectedDialer) lookupAddr(network string, domain string) (IPs []net.IP, err error) {
	underlyingResolver := d.GetResolver()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ok := make(chan interface{})
	defer cancel()

	var addrs []net.IP
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
			var str string
			str, err = underlyingResolver.LookupIP(network, domain)
			// java -> go
			if err != nil {
				rcode, err2 := strconv.Atoi(err.Error())
				if err2 == nil {
					err = dns.RCodeError(rcode)
				}
			} else if str == "" {
				err = dns.ErrEmptyResponse
			}
			addrs = make([]net.IP, 0)
			for _, ip := range strings.Split(str, ",") {
				addrs = append(addrs, net.ParseIP(ip))
			}
		} else {
			addrs, err = d.resolver.LookupIP(ctx, network, domain)
		}

		if err == nil && len(addrs) == 0 {
			err = dns.ErrEmptyResponse
		}
	}()

	select {
	case <-ctx.Done():
		return nil, errors.New("underlyingResolver: context cancelled")
	case <-ok:
	}

	if err == nil {
		IPs = reorderAddresses(addrs, d.preferIPv6)
	}

	return
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
		ips, err = d.lookupAddr("ip", dest.Address.Domain())
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
