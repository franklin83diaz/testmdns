package pkg

import (
	"fmt"
	"net"
)

func IpToPtr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip[3], ip[2], ip[1], ip[0])
}
