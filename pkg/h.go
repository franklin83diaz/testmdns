package pkg

import (
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

func HandlePacket(conn *net.UDPConn, remoteAddr net.Addr, requestBytes []byte) {
	// 1. Desempaquetamos el mensaje entrante.
	// El método Unpack() del Msg SÍ puede manejar múltiples preguntas.
	req := new(dns.Msg)
	err := req.Unpack(requestBytes)
	if err != nil {
		log.Printf("Error al desempaquetar la petición de %s: %v", remoteAddr.String(), err)
		return
	}

	// Verificamos que sea una consulta estándar.
	if req.Opcode != dns.OpcodeQuery {
		// No manejamos este tipo de mensajes.
		return
	}

	fmt.Printf("--> Petición recibida de %s con %d pregunta(s)\n", remoteAddr.String(), len(req.Question))
	for i, q := range req.Question {
		fmt.Printf("    Pregunta %d: %s, Tipo: %s\n", i+1, q.Name, dns.TypeToString[q.Qtype])
	}

	// 2. Creamos el mensaje de respuesta.
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	// 3. Iteramos sobre CADA pregunta y añadimos respuestas.
	for _, q := range req.Question {
		// Lógica de ejemplo para responder.
		var ip net.IP
		switch q.Name {
		case "servidor1.local.":
			ip = net.ParseIP("192.168.1.10")
		case "servidor2.local.":
			ip = net.ParseIP("192.168.1.20")
		case "base-de-datos.local.":
			ip = net.ParseIP("10.0.0.5")
		case "api.local.":
			ip = net.ParseIP("10.0.0.6")
		default:
			continue
		}

		if ip != nil && q.Qtype == dns.TypeA {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	if len(m.Answer) == 0 {
		m.SetRcode(req, dns.RcodeNameError) // NXDOMAIN
	}

	// 4. Empaquetamos la respuesta en bytes.
	responseBytes, err := m.Pack()
	if err != nil {
		log.Printf("Error al empaquetar la respuesta: %v", err)
		return
	}

	// 5. Enviamos los bytes de respuesta de vuelta al cliente.
	_, err = conn.WriteTo(responseBytes, remoteAddr)
	if err != nil {
		log.Printf("Error al enviar la respuesta a %s: %v", remoteAddr.String(), err)
	}
}
