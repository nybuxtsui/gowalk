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
		log.Fatalln("ca.Export failed:", err)
	}
	kb, err := p.key.ExportPrivate()
	if err != nil {
		log.Fatalln("ca.ExportPrivate failed:", err)
	}
	cert, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		log.Fatalln("X509KeyPair failed:", err)
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
	if depot.CheckCertificateAuthority(certLib) || depot.CheckCertificateAuthorityInfo(certLib) || depot.CheckPrivateKeyAuthority(certLib) {
		return true
	} else {
		return false
	}
}

func newCert(host string) (pair *certKeyPair, err error) {
	log.Println("new cert:", host)
	key, err := pkix.CreateRSAKey(1024)
	if err != nil {
		log.Println("CreateRSAKey failed:", err)
		return nil, err
	}
	csr, err := pkix.CreateCertificateSigningRequest(key, host, host)
	if err != nil {
		log.Println("CreateCertificateSigningRequest failed:", err)
		return nil, err
	}
	info := &pkix.CertificateAuthorityInfo{big.NewInt(certserid)}
	certserid++
	capair := loadCA()
	crtHost, err := pkix.CreateCertificateHost(capair.cert, info, capair.key, csr)
	if err != nil {
		log.Println("CreateCertificateHost failed:", err)
		return nil, err
	}
	return &certKeyPair{crtHost, key}, nil
}

func getCert(host string) (pair *certKeyPair, err error) {
	var ok bool
	if pair, ok = certMap[host]; ok {
		return
	}
	pair, err = newCert(host)
	if err == nil {
		certMap[host] = pair
	}
	return
}

func genCA() *certKeyPair {
	log.Println("CA not exist, generate!!!")
	key, err := pkix.CreateRSAKey(2048)
	if err != nil {
		log.Fatalln("CreateRSAKey failed:", err)
	}
	crt, info, err := pkix.CreateCertificateAuthority(key)
	if err != nil {
		log.Fatalln("CreateCertificateAuthority failed:", err)
	}

	if err = depot.PutCertificateAuthority(certLib, crt); err != nil {
		log.Fatalln("PutCertificateAuthority failed:", err)
	}
	if err = depot.PutCertificateAuthorityInfo(certLib, info); err != nil {
		log.Fatalln("PutCertificateAuthorityInfo failed:", err)
	}
	if err = depot.PutEncryptedPrivateKeyAuthority(certLib, key, passphrase); err != nil {
		log.Fatalln("PutCertificateAuthority failed:", err)
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
			log.Fatalln("GetCertificateAuthority failed:", err)
		}
		k, err := depot.GetEncryptedPrivateKeyAuthority(certLib, passphrase)
		if err != nil {
			log.Fatalln("GetEncryptedPrivateKeyAuthority failed:", err)
		}
		capair = &certKeyPair{c, k}
	}
	certMap[key] = capair
	return capair
}
