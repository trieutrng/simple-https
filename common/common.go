package common

// protocol version
type ProtocolVersion uint16

const (
	TLS_1_0 ProtocolVersion = 0x0301
	TLS_1_2 ProtocolVersion = 0x0303
	TLS_1_3 ProtocolVersion = 0x0304
)

type ExtensionType uint16

const (
	Ext_ServerName          ExtensionType = 0x00
	Ext_SupportedGroups     ExtensionType = 0x0a
	Ext_SignatureAlgorithms ExtensionType = 0x0d
	Ext_KeyShare            ExtensionType = 0x33
	Ext_PSKKeyExchangeModes ExtensionType = 0x2d
	Ext_SupportedVersions   ExtensionType = 0x2b
)

type ServerNameType byte

const (
	Host_Name ServerNameType = 0
)

type NamedCurve uint16

const (
	X25519 NamedCurve = 0x001d
)

type SignatureAlgorithm uint16

const (
	ECDSA_SECP256R1_SHA256 SignatureAlgorithm = 0x0403
	ECDSA_SECP384R1_SHA384 SignatureAlgorithm = 0x0503
	ECDSA_SECP521R1_SHA512 SignatureAlgorithm = 0x0603
	ED25519                SignatureAlgorithm = 0x0807
	ED448                  SignatureAlgorithm = 0x0808
	RSA_PSS_PSS_SHA256     SignatureAlgorithm = 0x0809
	RSA_PSS_PSS_SHA384     SignatureAlgorithm = 0x080a
	RSA_PSS_PSS_SHA512     SignatureAlgorithm = 0x080b
	RSA_PSS_RSAE_SHA256    SignatureAlgorithm = 0x0804
	RSA_PSS_RSAE_SHA384    SignatureAlgorithm = 0x0805
	RSA_PSS_RSAE_SHA512    SignatureAlgorithm = 0x0806
	RSA_PKCS1_SHA256       SignatureAlgorithm = 0x0401
	RSA_PKCS1_SHA384       SignatureAlgorithm = 0x0501
	RSA_PKCS1_SHA512       SignatureAlgorithm = 0x0601
	RSA_PKCS1_SHA1         SignatureAlgorithm = 0x0201
)

type PSKKeyExchangeMode uint8

const (
	PSK_DHE_KE PSKKeyExchangeMode = 0x01
)

const ClientHelloRandomLength = 32

// handshake type
type HandshakeType uint8

const (
	HandShake_ClientHello         HandshakeType = 0x01
	HandShake_ServerHello         HandshakeType = 0x02
	HandShake_EncryptedExtensions HandshakeType = 0x08
	HandShake_Certificate         HandshakeType = 0x0b
	HandShake_CertificateRequest  HandshakeType = 0x0d
	HandShake_CertificateVerify   HandshakeType = 0x0f
	HandShake_Finished            HandshakeType = 0x14
)

type CipherSuite uint16

const (
	TLS_AES_256_GCM_SHA384            CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256      CipherSuite = 0x1303
	TLS_AES_128_GCM_SHA256            CipherSuite = 0x1301
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV CipherSuite = 0x00ff
)

type ExchangeObject interface {
	Serialize() []byte
	Deserialize([]byte) int
}
