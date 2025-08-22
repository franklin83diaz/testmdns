package pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// Carga o genera una nueva CA.
func loadOrCreateCA() (*x509.Certificate, *rsa.PrivateKey) {
	certPath := "ca.crt"
	keyPath := "ca.key"

	// Si ya existen, los cargamos
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			ca, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				log.Fatalf("Error cargando la CA existente: %v", err)
			}
			x509Cert, err := x509.ParseCertificate(ca.Certificate[0])
			if err != nil {
				log.Fatalf("Error parseando el certificado de la CA: %v", err)
			}
			return x509Cert, ca.PrivateKey.(*rsa.PrivateKey)
		}
	}

	log.Println("Generando nueva CA...")
	// Crear una nueva CA
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2025),
		Subject: pkix.Name{
			Organization:  []string{"Mi Proxy MITM CA"},
			Country:       []string{"ES"},
			Province:      []string{""},
			Locality:      []string{"Madrid"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generar la clave privada para la CA
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Error generando la clave privada de la CA: %v", err)
	}

	// Crear el certificado de la CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Fatalf("Error creando el certificado de la CA: %v", err)
	}

	// Guardar el certificado de la CA en formato PEM
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err := os.WriteFile(certPath, caPEM, 0644); err != nil {
		log.Fatalf("Error guardando el certificado de la CA: %v", err)
	}

	// Guardar la clave privada de la CA
	caPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err := os.WriteFile(keyPath, caPrivKeyPEM, 0600); err != nil {
		log.Fatalf("Error guardando la clave de la CA: %v", err)
	}

	log.Printf("CA generada y guardada en %s y %s\n", certPath, keyPath)
	return ca, caPrivKey
}

// Genera un certificado para un host específico, firmado por nuestra CA.
func generateSignedCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, hostname string) (*tls.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	// Si el hostname es una IP, la añade a las IP SANs
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, hostname)
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
