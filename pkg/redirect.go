package pkg

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// pipeAndPrint copia datos entre dos conexiones y los imprime en consola.
func pipeAndPrint(src net.Conn, dst net.Conn, direction string) {
	defer src.Close()
	defer dst.Close()

	buf := make([]byte, 65535) // Buffer grande para capturar paquetes completos
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error de lectura en %s: %v", direction, err)
			}
			break
		}
		data := buf[:n]

		// Imprime los datos descifrados
		color := "\033[33m" // Amarillo para cliente -> servidor
		if direction == "servidor -> cliente" {
			color = "\033[36m" // Cyan para servidor -> cliente
		}
		fmt.Printf("%s--- %s ---\033[0m\n", color, direction)
		fmt.Printf("%s\n", string(data)) // Asume que es texto, podría ser binario
		fmt.Printf("%s-------------------------\033[0m\n", color)

		_, err = dst.Write(data)
		if err != nil {
			log.Printf("Error de escritura en %s: %v", direction, err)
			break
		}
	}
}

// RedirectTLS inicia el listener del proxy MITM.
func RedirectTLS() {
	caCert, caKey := loadOrCreateCA()

	// Cache para los certificados generados, para no recrearlos cada vez.
	certCache := &sync.Map{}

	// Configuración TLS para nuestro servidor (el que escucha al cliente)
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// El cliente nos dice a qué servidor quiere conectarse vía SNI
			serverName := hello.ServerName
			if serverName == "" {
				// Si SNI no está presente, podríamos usar la IP de destino.
				// Para Chromecast, SNI es fundamental.
				serverName = "192.168.2.172" // IP por defecto
			}

			log.Printf("Recibida petición TLS para: %s", serverName)

			// Buscamos en la cache
			if cert, ok := certCache.Load(serverName); ok {
				return cert.(*tls.Certificate), nil
			}

			// Si no está en cache, generamos uno nuevo
			log.Printf("Generando certificado para: %s", serverName)
			cert, err := generateSignedCert(caCert, caKey, serverName)
			if err != nil {
				log.Printf("Error generando certificado para %s: %v", serverName, err)
				return nil, err
			}

			// Guardamos en la cache
			certCache.Store(serverName, cert)
			return cert, nil
		},
	}

	ln, err := tls.Listen("tcp", "0.0.0.0:8009", tlsConfig)
	if err != nil {
		log.Fatalf("Error al iniciar el listener TLS: %v", err)
	}
	defer ln.Close()

	ipDevice := "192.168.2.172"
	log.Println("Escuchando en el puerto 8009 (con inspección TLS)")

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("Error al aceptar conexión: %v", err)
			continue
		}

		go handleConnection(clientConn, ipDevice)
	}
}

func handleConnection(clientConn net.Conn, ipDevice string) {
	defer clientConn.Close()
	fmt.Println("\033[34mNueva conexión TLS desde: ", clientConn.RemoteAddr(), "\033[0m")

	// Conectamos al servidor de destino real (Chromecast) con TLS
	destConn, err := tls.Dial("tcp", ipDevice+":8009", &tls.Config{
		// En un caso real, deberías validar el certificado del Chromecast.
		// Si el Chromecast usa un certificado autofirmado, puede que necesites
		// InsecureSkipVerify: true, pero es inseguro.
		// Lo ideal sería añadir la CA del Chromecast a un pool de CAs de confianza.
		InsecureSkipVerify: false,
	})

	if err != nil {
		log.Printf("No se pudo conectar al destino %s: %v", ipDevice, err)
		return
	}

	log.Printf("Conexión TLS establecida con el destino: %s", ipDevice)

	// Iniciar el copiado bidireccional con inspección
	go pipeAndPrint(clientConn, destConn, "cliente -> servidor")
	pipeAndPrint(destConn, clientConn, "servidor -> cliente")

	fmt.Println("\033[32mConexión cerrada desde: ", clientConn.RemoteAddr(), "\033[0m")
}
