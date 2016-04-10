package cryptoid

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
)

type PublicKeyAlgorithm struct {
	Name      string
	OID       asn1.ObjectIdentifier
	OIDString string
}

type HashAlgorithm struct {
	Name      string
	OID       asn1.ObjectIdentifier
	OIDString string
	Hash      crypto.Hash
}

// Satisfies crypto.SignerOpts interface for signing digests
// You can use a cryptoid.HashAlgorithm directly when
// using a crypto.Signer interface to sign digests.
func (h HashAlgorithm) HashFunc() crypto.Hash {
	return h.Hash
}

type SignatureAlgorithm struct {
	Name               string
	OID                asn1.ObjectIdentifier
	OIDString          string
	X509               x509.SignatureAlgorithm
	PublicKeyAlgorithm PublicKeyAlgorithm
	HashAlgorithm      HashAlgorithm
}

// Public Key Algorithms
// ---------------------

// RFC 3279, 2.3 Public Key Algorithms
var RSA = PublicKeyAlgorithm{
	Name:      "RSA",
	OID:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
	OIDString: "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1}",
}

// RFC 3279, 2.3 Public Key Algorithms
var DSA = PublicKeyAlgorithm{
	Name:      "DSA",
	OID:       asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1},
	OIDString: "{iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 1}",
}

// RFC 3279, Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure
var ECDSA = PublicKeyAlgorithm{
	Name:      "ECDSA",
	OID:       asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
	OIDString: "{iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1}",
}

// Hash Algorithms
// ---------------------

// RFC 1319, The MD2 Message-Digest Algorithm
var MD2 = HashAlgorithm{
	Name:      "MD2",
	OID:       asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 2},
	OIDString: "{iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 2}",
}

// RFC 1320, The MD4 Message-Digest Algorithm
var MD4 = HashAlgorithm{
	Name:      "MD4",
	OID:       asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 4},
	OIDString: "{iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 4}",
	Hash:      crypto.MD4,
}

// RFC 3370, Cryptographic Message Syntax (CMS) Algorithms
var MD5 = HashAlgorithm{
	Name:      "MD5",
	OID:       asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5},
	OIDString: "{iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5}",
	Hash:      crypto.MD5,
}

// RFC 3370, Cryptographic Message Syntax (CMS) Algorithms
var SHA1 = HashAlgorithm{
	Name:      "SHA1",
	OID:       asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
	OIDString: "{iso(1) identified-organization(3) oiw(14) secsig(3) algorithm(2) 26}",
	Hash:      crypto.SHA1,
}

// RFC 3874, A 224-bit One-way Hash Function: SHA-224
var SHA224 = HashAlgorithm{
	Name:      "SHA224",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) sha224(4)}",
	Hash:      crypto.SHA256,
}

// RFC 3560, Use of the RSAES-OAEP Key Transport Algorithm in the Cryptographic Message Syntax (CMS)
var SHA256 = HashAlgorithm{
	Name:      "SHA256",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 1}",
	Hash:      crypto.SHA256,
}

// RFC 3560, Use of the RSAES-OAEP Key Transport Algorithm in the Cryptographic Message Syntax (CMS)
var SHA384 = HashAlgorithm{
	Name:      "SHA384",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 2}",
	Hash:      crypto.SHA384,
}

// RFC 3560, Use of the RSAES-OAEP Key Transport Algorithm in the Cryptographic Message Syntax (CMS)
var SHA512 = HashAlgorithm{
	Name:      "SHA512",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 3}",
	Hash:      crypto.SHA512,
}

// RFC for SHA-3 is pending
var SHA3_224 = HashAlgorithm{
	Name:      "SHA3-224",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 7},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 7}",
	Hash:      crypto.SHA3_224,
}

// RFC for SHA-3 is pending
var SHA3_256 = HashAlgorithm{
	Name:      "SHA3-256",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 8}",
	Hash:      crypto.SHA3_256,
}

// RFC for SHA-3 is pending
var SHA3_384 = HashAlgorithm{
	Name:      "SHA3-384",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 9}",
	Hash:      crypto.SHA3_384,
}

// RFC for SHA-3 is pending
var SHA3_512 = HashAlgorithm{
	Name:      "SHA3-512",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 10}",
	Hash:      crypto.SHA3_512,
}

// RFC for SHA-3 is pending
var SHAKE128 = HashAlgorithm{
	Name:      "SHAKE128",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 11},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 11}",
}

// RFC for SHA-3 is pending
var SHAKE256 = HashAlgorithm{
	Name:      "SHAKE256",
	OID:       asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 12},
	OIDString: "{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 12}",
}

// Signature Algorithms
// --------------------

// RFC 3279 2.2.1 RSA Signature Algorithms
var MD2WithRSA = SignatureAlgorithm{
	Name:               "MD2-RSA",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2},
	OIDString:          "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) md2WithRSAEncryption(2)}",
	X509:               x509.MD2WithRSA,
	PublicKeyAlgorithm: RSA,
	HashAlgorithm:      MD2,
}

// RFC 3279 2.2.1 RSA Signature Algorithms
var MD4WithRSA = SignatureAlgorithm{
	Name:               "MD4-RSA",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 3},
	OIDString:          "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) md4WithRSAEncryption(3)}",
	X509:               x509.UnknownSignatureAlgorithm, // Not implemented in the x509 package
	PublicKeyAlgorithm: RSA,
	HashAlgorithm:      MD4,
}

// RFC 3279 2.2.1 RSA Signature Algorithms
var MD5WithRSA = SignatureAlgorithm{
	Name:               "MD5-RSA",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4},
	OIDString:          "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) md5WithRSAEncryption(4)}",
	X509:               x509.MD5WithRSA,
	PublicKeyAlgorithm: RSA,
	HashAlgorithm:      MD5,
}

// RFC 3279 2.2.1 RSA Signature Algorithms
var SHA1WithRSA = SignatureAlgorithm{
	Name:               "SHA1-RSA",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5},
	OIDString:          "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha1-with-rsa-signature(5)}",
	X509:               x509.SHA1WithRSA,
	PublicKeyAlgorithm: RSA,
	HashAlgorithm:      SHA1,
}

// RFC 4055 5 PKCS #1 Version 1.5
var SHA256WithRSA = SignatureAlgorithm{
	Name:               "SHA256-RSA",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
	OIDString:          "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha256WithRSAEncryption(11)}",
	X509:               x509.SHA256WithRSA,
	PublicKeyAlgorithm: RSA,
	HashAlgorithm:      SHA256,
}

// RFC 4055 5 PKCS #1 Version 1.5
var SHA384WithRSA = SignatureAlgorithm{
	Name:               "SHA384-RSA",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12},
	OIDString:          "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha384WithRSAEncryption(12)}",
	X509:               x509.SHA384WithRSA,
	PublicKeyAlgorithm: RSA,
	HashAlgorithm:      SHA384,
}

// RFC 4055 5 PKCS #1 Version 1.5
var SHA512WithRSA = SignatureAlgorithm{
	Name:               "SHA512-RSA",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13},
	OIDString:          "{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) sha384WithRSAEncryption(13)}",
	X509:               x509.SHA512WithRSA,
	PublicKeyAlgorithm: RSA,
	HashAlgorithm:      SHA512,
}

// RFC 3279 2.2.1 RSA Signature Algorithms
var DSAWithSHA1 = SignatureAlgorithm{
	Name:               "DSA-SHA1",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3},
	OIDString:          "{iso(1) member-body(2) us(840) x9-57(10040) x9algorithm(4) dsa-with-sha1(3)}",
	X509:               x509.DSAWithSHA1,
	PublicKeyAlgorithm: DSA,
	HashAlgorithm:      SHA1,
}

// RFC 5758 3.1 DSA Signature Algorithms
var DSAWithSHA256 = SignatureAlgorithm{
	Name:               "DSA-SHA256",
	OID:                asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2},
	OIDString:          "{joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) algorithms(4) id-dsa-with-sha2(3) 2}",
	X509:               x509.DSAWithSHA256,
	PublicKeyAlgorithm: DSA,
	HashAlgorithm:      SHA256,
}

// RFC 3279 2.2.3 ECDSA Signature Algorithm
var ECDSAWithSHA1 = SignatureAlgorithm{
	Name:               "ECDSA-SHA1",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1},
	OIDString:          "{iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA1(1)}",
	X509:               x509.ECDSAWithSHA1,
	PublicKeyAlgorithm: ECDSA,
	HashAlgorithm:      SHA1,
}

// RFC 5758 3.2 ECDSA Signature Algorithm
var ECDSAWithSHA256 = SignatureAlgorithm{
	Name:               "ECDSA-SHA256",
	OID:                asn1.ObjectIdentifier{2, 16, 840, 1, 101, 4, 3, 2},
	OIDString:          "{iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2}",
	X509:               x509.ECDSAWithSHA256,
	PublicKeyAlgorithm: ECDSA,
	HashAlgorithm:      SHA256,
}

// RFC 5758 3.2 ECDSA Signature Algorithm
var ECDSAWithSHA384 = SignatureAlgorithm{
	Name:               "ECDSA-SHA384",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3},
	OIDString:          "{iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3}",
	X509:               x509.ECDSAWithSHA384,
	PublicKeyAlgorithm: ECDSA,
	HashAlgorithm:      SHA384,
}

// RFC 5758 3.2 ECDSA Signature Algorithm
var ECDSAWithSHA512 = SignatureAlgorithm{
	Name:               "ECDSA-SHA512",
	OID:                asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4},
	OIDString:          "{iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4}",
	X509:               x509.ECDSAWithSHA512,
	PublicKeyAlgorithm: ECDSA,
	HashAlgorithm:      SHA512,
}
