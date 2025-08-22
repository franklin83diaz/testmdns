package pkg

import (
	"fmt"
	"log"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

var red = color.New(color.FgRed).SprintFunc()
var green = color.New(color.FgGreen).SprintFunc()
var yellow = color.New(color.FgYellow).SprintFunc()
var cyan = color.New(color.FgCyan).SprintFunc()
var blue = color.New(color.FgBlue).SprintFunc()

func Mdns(b []byte) []byte {
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Paquete DNS (tamaño %d bytes):\n", len(b))

	msg := new(dns.Msg)
	err := msg.Unpack(b)
	if err != nil {
		log.Printf("Error al desempaquetar el mensaje: %v\n", err)
		// Imprime el contenido para depuración aunque falle el desempaquetado
		fmt.Printf("Contenido (hex): % x\n", b)
		return nil
	}

	// Imprime la sección de Preguntas (si existe)
	if len(msg.Question) > 0 {
		fmt.Println("--- Preguntas ---")
		for i, q := range msg.Question {
			change := false

			// Solo nos interesa modificar las consultas de tipo PTR (búsqueda inversa de IP).
			// Si la pregunta es por el nombre asociado a ipDevice...
			if q.Qtype == dns.TypePTR && q.Name == PtrDevice {
				// ...la cambiamos para que pregunte por el nombre asociado a ipProxy.
				msg.Question[i] = dns.Question{
					Name:   PtrProxy,
					Qtype:  q.Qtype,
					Qclass: q.Qclass,
				}
				change = true
			}

			// NO modificamos las preguntas de tipo A, ya que esas preguntan por un nombre, no una IP.

			if change {
				fmt.Printf("	-%s\n", red(q.String()))
				fmt.Printf("	+%s\n", blue(msg.Question[i].String()))
			} else {
				fmt.Printf("	%s\n", q.String())
			}
		}
	}

	// Imprime la sección de Respuestas (si existe)
	if len(msg.Answer) > 0 {
		fmt.Println("--- Respuestas ---")
		for i, a := range msg.Answer {
			change := false
			// Address
			if a.Header().Rrtype == dns.TypeA {
				ip := a.(*dns.A).A.To4()
				if ip.Equal(IpDevice) {
					msg.Answer[i] = &dns.A{
						Hdr: dns.RR_Header{
							Name:   a.Header().Name,
							Rrtype: a.Header().Rrtype,
							Class:  a.Header().Class,
							Ttl:    a.Header().Ttl,
						},
						A: IpProxy,
					}
					change = true
				}
			}

			//Tipo PTR
			if a.Header().Rrtype == dns.TypePTR {
				ptr := a.(*dns.PTR)
				if PtrDevice == ptr.Hdr.Name {
					msg.Answer[i] = &dns.PTR{
						Hdr: dns.RR_Header{
							Name:   PtrProxy,
							Rrtype: a.Header().Rrtype,
							Class:  a.Header().Class,
							Ttl:    a.Header().Ttl,
						},
						Ptr: ptr.Ptr,
					}
					change = true
				}

			}
			if change {
				fmt.Printf("	-%s\n", red(a.String()))
				fmt.Printf("	+%s\n", blue(msg.Answer[i].String()))
			} else {
				fmt.Printf("	%s\n", a.String())
			}

		}
	}

	// Imprime la sección de Autoridad (si existe)
	if len(msg.Ns) > 0 {
		fmt.Println("--- Autoridad ---")
		for i, ns := range msg.Ns {
			change := false
			// Address
			if ns.Header().Rrtype == dns.TypeA {
				ip := ns.(*dns.A).A.To4()
				if ip.Equal(IpDevice) {
					msg.Ns[i] = &dns.A{
						Hdr: dns.RR_Header{
							Name:   ns.Header().Name,
							Rrtype: ns.Header().Rrtype,
							Class:  ns.Header().Class,
							Ttl:    ns.Header().Ttl,
						},
						A: IpProxy,
					}
					change = true
				}
			}

			//Tipo PTR
			if ns.Header().Rrtype == dns.TypePTR {
				ptr := ns.(*dns.PTR)
				if PtrDevice == ptr.Hdr.Name {
					msg.Ns[i] = &dns.PTR{
						Hdr: dns.RR_Header{
							Name:   PtrProxy,
							Rrtype: ns.Header().Rrtype,
							Class:  ns.Header().Class,
							Ttl:    ns.Header().Ttl,
						},
						Ptr: ptr.Ptr,
					}
					change = true
				}
			}

			if change {
				fmt.Printf("	-%s\n", red(ns.String()))
				fmt.Printf("	+%s\n", blue(msg.Ns[i].String()))
			} else {
				fmt.Printf("	%s\n", ns.String())
			}
		}
	}

	// Imprime la sección Adicional (si existe)
	if len(msg.Extra) > 0 {
		fmt.Println("--- Registros Adicionales ---")
		for i, e := range msg.Extra {
			change := false
			// Address
			if e.Header().Rrtype == dns.TypeA {
				ip := e.(*dns.A).A.To4()
				if ip.Equal(IpDevice) {
					msg.Extra[i] = &dns.A{
						Hdr: dns.RR_Header{
							Name:   e.Header().Name,
							Rrtype: e.Header().Rrtype,
							Class:  e.Header().Class,
							Ttl:    e.Header().Ttl,
						},
						A: IpProxy,
					}
					change = true
				}
			}

			//Tipo PTR
			if e.Header().Rrtype == dns.TypePTR {
				ptr := e.(*dns.PTR)
				if PtrDevice == ptr.Hdr.Name {
					msg.Extra[i] = &dns.PTR{
						Hdr: dns.RR_Header{
							Name:   PtrProxy,
							Rrtype: e.Header().Rrtype,
							Class:  e.Header().Class,
							Ttl:    e.Header().Ttl,
						},
						Ptr: ptr.Ptr,
					}
					change = true
				}
			}

			if change {
				fmt.Printf("	-%s\n", red(e.String()))
				fmt.Printf("	+%s\n", blue(msg.Extra[i].String()))
			} else {
				fmt.Printf("	%s\n", e.String())
			}
		}
	}
	//convert msg to []byte
	r, _ := msg.Pack()
	return r
}
