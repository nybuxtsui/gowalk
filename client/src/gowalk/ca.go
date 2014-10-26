package main

import (
	"crypto/tls"
	"github.com/nybuxtsui/ca/depot"
	"github.com/nybuxtsui/ca/pkix"
	"log"
	"math/big"
	"time"
)

type certKeyPair struct {
	cert *pkix.Certificate
	key  *pkix.Key
}

func (p *certKeyPair) toX509Pair() tls.Certificate {
	cb, err := p.cert.Export()
	if err != nil {
		log.Fatalln("Export cert failed:", err)
	}
	kb, err := p.key.ExportPrivate()
	if err != nil {
		log.Fatalln("Export private failed:", err)
	}
	cert, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		log.Fatalln("Make X509 KeyPair failed:", err)
	}
	return cert
}

var (
	passphrase = []byte("^BM*N))%V$")
	certLib    *depot.FileDepot
	certserid  int64 = time.Now().UnixNano()

	certMap = make(map[string]*certKeyPair)
)

func isCAExist() bool {
	if depot.CheckCertificateAuthority(certLib) || depot.CheckPrivateKeyAuthority(certLib) {
		return true
	} else {
		return false
	}
}

func loadCert(host string) (pair *certKeyPair) {
	if depot.CheckCertificateHost(certLib, host) {
		crtHost, err := depot.GetCertificateHost(certLib, host)
		if err != nil {
			log.Println("Load cert failed:", err)
			return nil
		}
		key, err := depot.GetPrivateKeyHost(certLib, host)
		if err != nil {
			log.Println("Load cert failed:", err)
			return nil
		}
		return &certKeyPair{crtHost, key}
	}
	return nil
}

func newCert(host string) (pair *certKeyPair, err error) {
	log.Println("Create cert for host:", host)
	key, err := pkix.CreateRSAKey(1024)
	if err != nil {
		log.Println("Create RSA key failed:", err)
		return nil, err
	}
	csr, err := pkix.CreateCertificateSigningRequest(key, host, host)
	if err != nil {
		log.Println("Create CSR failed:", err)
		return nil, err
	}
	info := &pkix.CertificateAuthorityInfo{big.NewInt(certserid)}
	certserid++
	capair := loadCA()
	crtHost, err := pkix.CreateCertificateHost(capair.cert, info, capair.key, csr)
	if err != nil {
		log.Println("Create cert failed:", err)
		return nil, err
	}
	err = depot.PutCertificateHost(certLib, host, crtHost)
	if err != nil {
		log.Println("Save cert failed:", err)
		return nil, err
	}
	err = depot.PutPrivateKeyHost(certLib, host, key)
	if err != nil {
		log.Println("Save key failed:", err)
		return nil, err
	}
	return &certKeyPair{crtHost, key}, nil
}

func getCert(host string) (pair *certKeyPair, err error) {
	var ok bool
	if pair, ok = certMap[host]; ok {
		return
	}
	pair = loadCert(host)
	if pair != nil {
		certMap[host] = pair
		return
	}
	pair, err = newCert(host)
	if err == nil {
		certMap[host] = pair
	}
	return
}

func genCA() *certKeyPair {
	log.Println("Generate CA")
	key, err := pkix.CreateRSAKey(2048)
	if err != nil {
		log.Fatalln("Create RSA key failed:", err)
		return nil
	}
	crt, _, err := pkix.CreateCertificateAuthority(key)
	if err != nil {
		log.Fatalln("Create CA failed:", err)
		return nil
	}

	if err = depot.PutCertificateAuthority(certLib, crt); err != nil {
		log.Fatalln("Save CA failed:", err)
		return nil
	}
	if err = depot.PutEncryptedPrivateKeyAuthority(certLib, key, passphrase); err != nil {
		log.Fatalln("Save CA private key failed:", err)
		return nil
	}
	return &certKeyPair{crt, key}
}

func loadCA() *certKeyPair {
	const key = "__CA__"
	pair, ok := certMap[key]
	if ok {
		return pair
	}
	var capair *certKeyPair
	if !isCAExist() {
		capair = genCA()
	} else {
		var err error
		c, err := depot.GetCertificateAuthority(certLib)
		if err != nil {
			log.Fatal("LoadCA|GetCertificateAuthority|%v", err)
			return nil
		}
		k, err := depot.GetEncryptedPrivateKeyAuthority(certLib, passphrase)
		if err != nil {
			log.Fatal("LoadCA|GetEncryptedPrivateKeyAuthority|%v", err)
			return nil
		}
		capair = &certKeyPair{c, k}
	}
	certMap[key] = capair
	return capair
}
