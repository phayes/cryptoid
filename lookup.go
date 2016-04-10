package cryptoid

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// Errors
var UnableToFind = errors.New("cryptoid: Unable to find cryptosystem with that identifier")

func PublicKeyAlgorithmByOID(oid string) (PublicKeyAlgorithm, error) {
	item := LookupByOID(oid)
	algo, ok := item.(PublicKeyAlgorithm)
	if !ok {
		return PublicKeyAlgorithm{}, UnableToFind
	}
	return algo, nil
}

func HashAlgorithmByOID(oid string) (HashAlgorithm, error) {
	item := LookupByOID(oid)
	algo, ok := item.(HashAlgorithm)
	if !ok {
		return HashAlgorithm{}, UnableToFind
	}
	return algo, nil
}

func SignatureAlgorithmByOID(oid string) (SignatureAlgorithm, error) {
	item := LookupByOID(oid)
	algo, ok := item.(SignatureAlgorithm)
	if !ok {
		return SignatureAlgorithm{}, UnableToFind
	}
	return algo, nil
}

func LookupByOID(oid string) interface{} {
	if len(oid) == 0 {
		return nil
	}

	switch oid {
	case "1.2.840.113549.1.1.1":
		return RSA
	case "1.2.840.10040.4.1":
		return DSA
	case "1.2.840.10045.2.1":
		return ECDSA
	case "1.2.840.113549.2.2":
		return MD2
	case "1.2.840.113549.2.4":
		return MD4
	case "1.2.840.113549.2.5":
		return MD5
	case "1.3.14.3.2.26":
		return SHA1
	case "2.16.840.1.101.3.4.2.4":
		return SHA224
	case "2.16.840.1.101.3.4.2.1":
		return SHA256
	case "2.16.840.1.101.3.4.2.2":
		return SHA384
	case "2.16.840.1.101.3.4.2.3":
		return SHA512
	case "2.16.840.1.101.3.4.2.7":
		return SHA3_224
	case "2.16.840.1.101.3.4.2.8":
		return SHA3_256
	case "2.16.840.1.101.3.4.2.9":
		return SHA3_384
	case "2.16.840.1.101.3.4.2.10":
		return SHA3_512
	case "2.16.840.1.101.3.4.2.11":
		return SHAKE128
	case "2.16.840.1.101.3.4.2.12":
		return SHAKE256
	case "1.2.840.113549.1.1.2":
		return MD2WithRSA
	case "1.2.840.113549.1.1.3":
		return MD4WithRSA
	case "1.2.840.113549.1.1.4":
		return MD5WithRSA
	case "1.2.840.113549.1.1.5":
		return SHA1WithRSA
	case "1.2.840.113549.1.1.11":
		return SHA256WithRSA
	case "1.2.840.113549.1.1.12":
		return SHA384WithRSA
	case "1.2.840.113549.1.1.13":
		return SHA512WithRSA
	case "1.2.840.10040.4.3":
		return DSAWithSHA1
	case "2.16.840.1.101.3.4.3.2":
		return DSAWithSHA256
	case "1.2.840.10045.4.1":
		return ECDSAWithSHA1
	case "2.16.840.1.101.4.3.2":
		return ECDSAWithSHA256
	case "2.16.840.1.101.4.3.3":
		return ECDSAWithSHA384
	case "2.16.840.1.101.4.3.4":
		return ECDSAWithSHA512
	default:
		return nil
	}
}

func PublicKeyAlgorithmByName(name string) (PublicKeyAlgorithm, error) {
	item := LookupByName(name)
	algo, ok := item.(PublicKeyAlgorithm)
	if !ok {
		return PublicKeyAlgorithm{}, UnableToFind
	}
	return algo, nil
}

func HashAlgorithmByName(name string) (HashAlgorithm, error) {
	item := LookupByName(name)
	algo, ok := item.(HashAlgorithm)
	if !ok {
		return HashAlgorithm{}, UnableToFind
	}
	return algo, nil
}

func SignatureAlgorithmByName(name string) (SignatureAlgorithm, error) {
	item := LookupByName(name)
	algo, ok := item.(SignatureAlgorithm)
	if !ok {
		return SignatureAlgorithm{}, UnableToFind
	}
	return algo, nil
}

func LookupByName(name string) interface{} {
	switch name {
	case "RSA":
		return RSA
	case "DSA":
		return DSA
	case "ECDSA":
		return ECDSA
	case "MD2":
		return MD2
	case "MD4":
		return MD4
	case "MD5":
		return MD5
	case "SHA1":
		return SHA1
	case "SHA224":
		return SHA224
	case "SHA256":
		return SHA256
	case "SHA384":
		return SHA384
	case "SHA512":
		return SHA512
	case "SHA3-224":
		return SHA3_224
	case "SHA3-256":
		return SHA3_256
	case "SHA3-384":
		return SHA3_384
	case "SHA3-512":
		return SHA3_512
	case "SHAKE128":
		return SHAKE128
	case "SHAKE256":
		return SHAKE256
	case "MD2WithRSA":
		return MD2WithRSA
	case "MD4WithRSA":
		return MD4WithRSA
	case "MD5WithRSA":
		return MD5WithRSA
	case "SHA1WithRSA":
		return SHA1WithRSA
	case "SHA256WithRSA":
		return SHA256WithRSA
	case "SHA384WithRSA":
		return SHA384WithRSA
	case "SHA512WithRSA":
		return SHA512WithRSA
	case "DSAWithSHA1":
		return DSAWithSHA1
	case "DSAWithSHA256":
		return DSAWithSHA256
	case "ECDSAWithSHA1":
		return ECDSAWithSHA1
	case "ECDSAWithSHA256":
		return ECDSAWithSHA256
	case "ECDSAWithSHA384":
		return ECDSAWithSHA384
	case "ECDSAWithSHA512":
		return ECDSAWithSHA512
	default:
		return nil
	}
}

func HashAlgorithmByCrypto(hash crypto.Hash) HashAlgorithm {
	switch hash {
	case crypto.MD4:
		return MD4, nil
	case crypto.MD5:
		return MD5, nil
	case crypto.SHA1:
		return SHA1, nil
	case crypto.SHA224:
		return SHA224, nil
	case crypto.SHA256:
		return SHA256, nil
	case crypto.SHA384:
		return SHA384, nil
	case crypto.SHA512:
		return SHA512, nil
	case crypto.SHA3_224:
		return SHA3_224, nil
	case crypto.SHA3_256:
		return SHA3_256, nil
	case crypto.SHA3_384:
		return SHA3_384, nil
	case crypto.SHA3_512:
		return SHA3_512, nil
	default:
		panic("Invalid crypto.Hash") // This shouldn't be possible
	}
}

func SignatureAlgorithmByX509(sig x509.SignatureAlgorithm) (SignatureAlgorithm, error) {
	switch sig {
	case x509.MD2WithRSA:
		return MD2WithRSA, nil
	case x509.MD5WithRSA:
		return MD5WithRSA, nil
	case x509.SHA1WithRSA:
		return SHA1WithRSA, nil
	case x509.SHA256WithRSA:
		return SHA256WithRSA, nil
	case x509.SHA384WithRSA:
		return SHA384WithRSA, nil
	case x509.SHA512WithRSA:
		return SHA512WithRSA, nil
	case x509.DSAWithSHA1:
		return DSAWithSHA1, nil
	case x509.DSAWithSHA256:
		return DSAWithSHA256, nil
	case x509.ECDSAWithSHA1:
		return ECDSAWithSHA1, nil
	case x509.ECDSAWithSHA256:
		return ECDSAWithSHA256, nil
	case x509.ECDSAWithSHA384:
		return ECDSAWithSHA384, nil
	case x509.ECDSAWithSHA512:
		return ECDSAWithSHA512, nil
	default:
		return SignatureAlgorithm{}, UnableToFind
	}
}
