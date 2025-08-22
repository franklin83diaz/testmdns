// go.mod:  require github.com/coreos/go-iptables/iptables v0.7.0
package pkg

import (
	"fmt"
	"net"

	"github.com/coreos/go-iptables/iptables"
)

type Manager struct {
	ipt *iptables.IPTables
}

// New crea un manager para IPv4.
func New() (*Manager, error) {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}
	return &Manager{ipt: ipt}, nil
}

func isIPv4(s string) bool { ip := net.ParseIP(s); return ip != nil && ip.To4() != nil }

// AddRedirect crea la regla:
// nat/PREROUTING: -s SRC -p udp ! --dport 5353 -j DNAT --to-destination DST
func (m *Manager) AddRedirect(srcIP, dstIP string) error {
	if !isIPv4(srcIP) || !isIPv4(dstIP) {
		return fmt.Errorf("IPs inválidas (solo IPv4): src=%q dst=%q", srcIP, dstIP)
	}
	rule := []string{
		"-s", srcIP,
		"-p", "udp", "!", "--dport", "5353",
		"-m", "comment", "--comment", "redir-udp-except-5353",
		"-j", "DNAT", "--to-destination", dstIP,
	}
	return m.ipt.AppendUnique("nat", "PREROUTING", rule...)
}

// DelRedirect borra exactamente la misma regla creada por AddRedirect.
func (m *Manager) DelRedirect(srcIP, dstIP string) error {
	rule := []string{
		"-s", srcIP,
		"-p", "udp", "!", "--dport", "5353",
		"-m", "comment", "--comment", "redir-udp-except-5353",
		"-j", "DNAT", "--to-destination", dstIP,
	}
	return m.ipt.Delete("nat", "PREROUTING", rule...)
}

// (Opcional) Si el retorno no vuelve por esta máquina, agrega MASQUERADE en POSTROUTING.
func (m *Manager) AddMasquerade(outIf string) error {
	rule := []string{
		"-p", "udp", "-o", outIf,
		"-m", "comment", "--comment", "redir-udp-except-5353-masq",
		"-j", "MASQUERADE",
	}
	return m.ipt.AppendUnique("nat", "POSTROUTING", rule...)
}

func (m *Manager) DelMasquerade(outIf string) error {
	rule := []string{
		"-p", "udp", "-o", outIf,
		"-m", "comment", "--comment", "redir-udp-except-5353-masq",
		"-j", "MASQUERADE",
	}
	return m.ipt.Delete("nat", "POSTROUTING", rule...)
}
