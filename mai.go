package main

import (
	"log"
	"net"
	"os"
	"testmdns/pkg"
)

func main() {

	if len(os.Args) < 5 {
		log.Fatalf("Uso: %s <interface client> <interface devices> <ipDevice> <ipProxy>", os.Args[0])
	}

	go pkg.Redirect()

	addr := "224.0.0.251:5353"
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("Fallo al resolver la dirección UDP: %s", err)
	}
	iface1Name := os.Args[1]
	iface2Name := os.Args[2]
	pkg.IpDevice = net.ParseIP(os.Args[3])
	pkg.IpProxy = net.ParseIP(os.Args[4])

	pkg.PtrDevice = pkg.IpToPtr(pkg.IpDevice)
	pkg.PtrProxy = pkg.IpToPtr(pkg.IpProxy)

	if pkg.IpDevice == nil || pkg.IpProxy == nil {
		log.Fatalf("Fallo al analizar las direcciones IP: %s", err)
	}

	iface1, err := net.InterfaceByName(iface1Name)
	if err != nil {
		log.Fatalf("Fallo al obtener la interfaz de red: %s", err)
	}

	iface2, err := net.InterfaceByName(iface2Name)
	if err != nil {
		log.Fatalf("Fallo al obtener la interfaz de red: %s", err)
	}

	// mgr, _ := pkg.New()
	// _ = mgr.AddRedirect(pkg.IpDevice.String(), pkg.IpProxy.String()) // añade DNAT (excepto 5353)
	// _ = mgr.AddMasquerade(iface2Name)

	conn1, err := net.ListenMulticastUDP("udp4", iface1, udpAddr)
	if err != nil {
		log.Fatalf("Fallo al iniciar el listener UDP: %s", err)
	}
	defer conn1.Close()

	conn2, err := net.ListenMulticastUDP("udp4", iface2, udpAddr)
	if err != nil {
		log.Fatalf("Fallo al iniciar el listener UDP: %s", err)
	}
	defer conn2.Close()

	go func() {
		for {
			// Leemos el paquete UDP entrante.
			buf := make([]byte, 4000) // Tamaño estándar para DNS sobre UDP.
			n, _, err := conn2.ReadFrom(buf)
			//	fmt.Printf("Paquete recibido de %s\n", remoteAddr.String())
			if err != nil {
				log.Printf("Error al leer del socket UDP: %v", err)
				continue
			}

			//write to 224.0.0.251:5353
			conn2.WriteTo(pkg.Mdns(buf[:n]), &net.UDPAddr{
				IP:   net.ParseIP("224.0.0.251"),
				Port: 5353,
			})
		}
	}()

	for {
		// Leemos el paquete UDP entrante.
		buf := make([]byte, 4000) // Tamaño estándar para DNS sobre UDP.
		n, _, err := conn1.ReadFrom(buf)
		//fmt.Printf("Paquete recibido de %s\n", remoteAddr.String())
		if err != nil {
			log.Printf("Error al leer del socket UDP: %v", err)
			continue
		}

		//write to 224.0.0.251:5353
		conn1.WriteTo(pkg.Mdns(buf[:n]), &net.UDPAddr{
			IP:   net.ParseIP("224.0.0.251"),
			Port: 5353,
		})

	}
}
