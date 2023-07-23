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

	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	v2internet "github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

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
		IPs = make([]net.IP, 0)
		//ipv6 is prefer, append ipv6 then ipv4
		//ipv6 is not prefer, append ipv4 then ipv6
		if d.preferIPv6 {
			for _, ip := range addrs {
				if ip.To4() == nil {
					IPs = append(IPs, ip)
				}
			}
		}
		for _, ip := range addrs {
			if ip.To4() != nil {
				IPs = append(IPs, ip)
			}
		}
		if !d.preferIPv6 {
			for _, ip := range addrs {
				if ip.To4() == nil {
					IPs = append(IPs, ip)
				}
			}
		}
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

	if dest.Address.Family().IsIP() && FAKEDNS_VLAN4_CLIENT_IPNET.Contains(dest.Address.IP()) {
		// fake ip
		outbound := session.OutboundFromContext(ctx)
		if outbound == nil || !outbound.Target.IsValid() {
			return nil, errors.New("target not specified")
		}

		dest = outbound.Target
	}

	var ips []net.IP
	if dest.Address.Family().IsDomain() {
		ips, err = d.lookupAddr("ip", dest.Address.Domain())
		if err != nil {
			return nil, err
		}
	} else {
		ips = []net.IP{dest.Address.IP()}
	}

	for i, ip := range ips {
		if i > 0 {
			if err == nil {
				break
			} else {
				log.Printf("dial system failed, Err: %s\n", err.Error())
				time.Sleep(time.Millisecond * 200)
			}
			log.Printf("trying next address: %s", ip.String())
		}
		conn, err = d.fdConn(ctx, dest.Network, ip, int(dest.Port))
	}

	return conn, err
}

func (d *ProtectedDialer) fdConn(ctx context.Context, network v2net.Network, ip net.IP, port int) (net.Conn, error) {
	fd, err := d.getFd(network)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	// call android VPN service to "protect" the fd connecting straight out
	if !d.Protect(fd) {
		log.Printf("fdConn fail to protect, Close Fd: %d", fd)
		return nil, errors.New("fail to protect")
	}

	sa := &unix.SockaddrInet6{
		Port: port,
	}
	copy(sa.Addr[:], ip.To16())

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
