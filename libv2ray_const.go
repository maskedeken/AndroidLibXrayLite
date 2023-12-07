package libv2ray

import "net"

const LOCALHOST = "127.0.0.1"
const PRIVATE_VLAN4_CLIENT = "26.26.26.1"
const PRIVATE_VLAN4_ROUTER = "26.26.26.2"
const PRIVATE_VLAN6_CLIENT = "da26:2626::1"
const PRIVATE_VLAN6_ROUTER = "da26:2626::2"

const TEST_DESTINATION_IPV4 = "udp:8.8.8.8:0"
const TEST_DESTINATION_IPV6 = "udp:[2000::]:0"

var FAKEDNS_VLAN4_CLIENT_IPNET = net.IPNet{IP: net.ParseIP("198.18.0.0").To4(), Mask: net.CIDRMask(15, 32)}
var FAKEDNS_VLAN6_CLIENT_IPNET = net.IPNet{IP: net.ParseIP("fc00::").To16(), Mask: net.CIDRMask(18, 128)}
