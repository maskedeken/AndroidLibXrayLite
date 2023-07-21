package libv2ray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	v2internet "github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

type protectSet interface {
	Protect(int) bool
	GetResolver() UnderlyingResolver
}

type resolved struct {
	domain       string
	IPs          []net.IP
	Port         int
	lastResolved time.Time
	ipIdx        uint8
	ipLock       sync.Mutex
	lastSwitched time.Time
}

// NextIP switch to another resolved result.
// there still be race-condition here if multiple err concurently occured
// may cause idx keep switching,
// but that's an outside error can hardly handled here
func (r *resolved) NextIP() {
	r.ipLock.Lock()
	defer r.ipLock.Unlock()

	if len(r.IPs) > 1 {

		// throttle, don't switch too quickly
		now := time.Now()
		if now.Sub(r.lastSwitched) < time.Second*5 {
			log.Println("switch too quickly")
			return
		}
		r.lastSwitched = now
		r.ipIdx++

	} else {
		return
	}

	if r.ipIdx >= uint8(len(r.IPs)) {
		r.ipIdx = 0
	}

	log.Printf("switched to next IP: %v", r.IPs[r.ipIdx])
}

func (r *resolved) currentIP() net.IP {
	r.ipLock.Lock()
	defer r.ipLock.Unlock()
	if len(r.IPs) > 0 {
		return r.IPs[r.ipIdx]
	}

	return nil
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

	vServer  *resolved
	resolver *net.Resolver

	protectSet
}

// simplicated version of golang: internetAddrList in src/net/ipsock.go
func (d *ProtectedDialer) lookupAddr(addr string) (*resolved, error) {

	var (
		err        error
		host, port string
		portnum    int
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if host, port, err = net.SplitHostPort(addr); err != nil {
		log.Printf("PrepareDomain SplitHostPort Err: %v", err)
		return nil, err
	}

	if portnum, err = d.resolver.LookupPort(ctx, "tcp", port); err != nil {
		log.Printf("PrepareDomain LookupPort Err: %v", err)
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return &resolved{
			domain:       host,
			IPs:          []net.IP{ip},
			Port:         portnum,
			lastResolved: time.Now(),
		}, nil
	}

	var addrs []net.IP
	underlyingResolver := d.GetResolver()
	if underlyingResolver != nil {
		var str string
		str, err = underlyingResolver.LookupIP("ip", host)
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
		addrs, err = d.resolver.LookupIP(ctx, "ip", host)
	}
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("domain %s Failed to resolve", addr)
	}

	IPs := make([]net.IP, 0)
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

	rs := &resolved{
		domain:       host,
		IPs:          IPs,
		Port:         portnum,
		lastResolved: time.Now(),
	}

	return rs, nil
}

func (d *ProtectedDialer) getFd(network v2net.Network) (fd int, err error) {
	switch network {
	case v2net.Network_TCP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	case v2net.Network_UDP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	default:
		err = fmt.Errorf("unknow network")
	}
	return
}

// Init implement internet.SystemDialer
func (d *ProtectedDialer) Init(_ dns.Client, _ outbound.Manager) {
	// do nothing
}

// Dial exported as the protected dial method
func (d *ProtectedDialer) Dial(ctx context.Context,
	src v2net.Address, dest v2net.Destination, sockopt *v2internet.SocketConfig) (net.Conn, error) {

	network := dest.Network.SystemString()
	Address := dest.NetAddr()

	// v2ray server address,
	// try to connect fixed IP if multiple IP parsed from domain,
	// and switch to next IP if error occurred
	if Address == d.currentServer {
		if d.vServer == nil {
			rs, err := d.lookupAddr(Address)
			if err != nil {
				return nil, err
			}

			d.vServer = rs
		}

		// if time.Since(d.vServer.lastResolved) > time.Minute*30 {
		// 	go d.PrepareDomain(Address, nil, d.preferIPv6)
		// }

		fd, err := d.getFd(dest.Network)
		if err != nil {
			return nil, err
		}

		curIP := d.vServer.currentIP()
		conn, err := d.fdConn(ctx, curIP, d.vServer.Port, fd)
		if err != nil {
			d.vServer.NextIP()
			return nil, err
		}
		log.Printf("Using Prepared: %s", curIP)
		return conn, nil
	}

	// v2ray connecting to "domestic" servers, no caching results
	log.Printf("Not Using Prepared: %s,%s", network, Address)
	resolved, err := d.lookupAddr(Address)
	if err != nil {
		return nil, err
	}

	fd, err := d.getFd(dest.Network)
	if err != nil {
		return nil, err
	}

	// use the first resolved address.
	// the result IP may vary, eg: IPv6 addrs comes first if client has ipv6 address
	return d.fdConn(ctx, resolved.IPs[0], resolved.Port, fd)
}

func (d *ProtectedDialer) fdConn(ctx context.Context, ip net.IP, port int, fd int) (net.Conn, error) {

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
