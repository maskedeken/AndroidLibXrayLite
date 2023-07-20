package tun

import (
	"net"

	v2rayNet "github.com/xtls/xray-core/common/net"
)

type Tun interface {
	Close()
}

// For UDP downlink
type WriteBackFunc func([]byte, *net.UDPAddr) (int, error)

// For UDP upLink
type UDPPacket struct {
	Src       *net.UDPAddr
	Dst       *net.UDPAddr
	Data      []byte
	WriteBack WriteBackFunc
}

type Handler interface {
	NewConnection(source v2rayNet.Destination, destination v2rayNet.Destination, conn net.Conn)
	HandlePacket(p *UDPPacket) // Handle Uplink UDP Packet
}

const PRIVATE_VLAN4_CLIENT = "26.26.26.1"
const PRIVATE_VLAN4_ROUTER = "26.26.26.2"
const PRIVATE_VLAN6_CLIENT = "da26:2626::1"
const PRIVATE_VLAN6_ROUTER = "da26:2626::2"

var FAKEDNS_VLAN4_CLIENT_IPNET = net.IPNet{IP: net.ParseIP("198.18.0.0").To4(), Mask: net.CIDRMask(15, 32)}
