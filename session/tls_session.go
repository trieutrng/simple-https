package session

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"trieutrng.com/toy-tls/common"
	"trieutrng.com/toy-tls/crypto"
	"trieutrng.com/toy-tls/protocol"
	"trieutrng.com/toy-tls/protocol/client"
	"trieutrng.com/toy-tls/protocol/server"
)

type TLSSession struct {
	conn           net.Conn
	domain         string
	keys           *keys
	keyCalcRecords []*protocol.Record
}

type keys struct {
	clientKeyPair   *crypto.KeyPair
	serverPublicKey []byte
	sessionKey      []byte
	handShakeKeys   *handShakeKeys
	applicationKeys *applicationKeys
}

type handShakeKeys struct {
	handShakeSecret    []byte
	clientSecret       []byte
	serverSecret       []byte
	clientHandShakeKey []byte
	serverHandShakeKey []byte
	clientHandShakeIV  []byte // initialization vector
	serverHandShakeIV  []byte // initialization vector
}

type applicationKeys struct {
	clientApplicationKey []byte
	serverApplicationKey []byte
	clientApplicationIV  []byte // initialization vector
	serverApplicationIV  []byte // initialization vector
}

func NewSession(domain string) (*TLSSession, error) {
	conn, err := openTcp(domain)
	if err != nil {
		return nil, err
	}

	tlsSession := &TLSSession{
		conn:   conn,
		domain: domain,
		keys:   &keys{},
	}

	err = tlsSession.handShake()
	if err != nil {
		return nil, err
	}

	return tlsSession, nil
}

func (s *TLSSession) Write(input []byte) error {
	return nil // TODO
}

func (s *TLSSession) Read() ([]byte, error) {
	return nil, nil // TODO
}

func (s *TLSSession) handShake() error {
	if err := s.generateKeyExchange(); err != nil {
		log.Errorf("Failed to generate key pair: %v", err)
		return err
	}
	if err := s.clientHello(); err != nil {
		log.Errorf("Failed to send client hello: %v", err)
		return err
	}
	if err := s.serverHello(); err != nil {
		log.Errorf("Failed to receive server hello: %v", err)
		return err
	}
	if err := s.calculateHandshakeKeys(); err != nil {
		log.Errorf("Failed to calculate handshake keys: %v", err)
		return err
	}
	if err := s.serverChangeCipherSpec(); err != nil {
		log.Errorf("Failed on receiving server change cipher spec: %v", err)
		return err
	}
	return nil
}

func (s *TLSSession) generateKeyExchange() error {
	keyPair, err := crypto.GetX25519KeyPair()
	if err != nil {
		return err
	}
	s.keys.clientKeyPair = keyPair
	return nil
}

func (s *TLSSession) clientHello() error {
	record, err := s.getClientHelloRecord()
	if err != nil {
		return err
	}

	n, err := s.conn.Write(record.Serialize())
	if err != nil {
		return err
	}

	s.keyCalcRecords = append(s.keyCalcRecords, record)
	log.Debugf("Exchanged %v bytes of client hello record", n)

	return nil
}

func (s *TLSSession) serverHello() error {
	record, err := s.getRecord()
	if err != nil {
		return err
	}

	serverHandshake := (record.Fragment).(*protocol.HandShake)
	serverHello := (serverHandshake.Body).(*protocol.ServerHello)

	s.keyCalcRecords = append(s.keyCalcRecords, record)

	log.Debugf("Server chose cipher suite: %v\n", serverHello.CipherSuite)

	var serverPublicKey []byte
	for _, ext := range serverHello.Extensions.Data {
		if extKeyShare, ok := (ext.Data).(*server.ExtKeyShare); ok {
			serverPublicKey = extKeyShare.KeyExchange
			break
		}
	}
	if serverPublicKey == nil {
		return errors.New("server turn no public key")
	}
	s.keys.serverPublicKey = serverPublicKey
	return nil
}

func (s *TLSSession) calculateHandshakeKeys() error {
	// calculate shared secret
	sharedSecret, err := crypto.GetSharedSecretX25519(s.keys.clientKeyPair.Private, s.keys.serverPublicKey)
	if err != nil {
		return err
	}

	// calculate hello hash
	concatenatedHello := make([]byte, 0)
	for _, record := range s.keyCalcRecords {
		concatenatedHello = append(concatenatedHello, record.Fragment.Serialize()...)
	}

	// calculate handshake keys
	// use sha256 hash func here since the server and client has been accepted on cipher suite with SHA256
	hashFunc := sha256.New
	hashLength := 32

	hashMessage := func(message []byte) []byte {
		hashedMessage := sha256.Sum256(message)
		return hashedMessage[:]
	}

	var empty []byte
	zeroSalt := make([]byte, 32)
	zeroSecret := make([]byte, 32)

	earlySecret := crypto.HKDFExtract(hashFunc, zeroSecret, zeroSalt)
	derivedSecret := crypto.HKDFExpandLabel(hashFunc, earlySecret, "derived", hashMessage(empty), hashLength)
	handShakeSecret := crypto.HKDFExtract(hashFunc, sharedSecret, derivedSecret)

	clientSecret := crypto.HKDFExpandLabel(hashFunc, handShakeSecret, "c hs traffic", hashMessage(concatenatedHello), hashLength)
	clientHandShakeKey := crypto.HKDFExpandLabel(hashFunc, clientSecret, "key", empty, 16)
	clientHandShakeIV := crypto.HKDFExpandLabel(hashFunc, clientSecret, "iv", empty, 12)

	serverSecret := crypto.HKDFExpandLabel(hashFunc, handShakeSecret, "s hs traffic", hashMessage(concatenatedHello), hashLength)
	serverHandShakeKey := crypto.HKDFExpandLabel(hashFunc, serverSecret, "key", empty, 16)
	serverHandShakeIV := crypto.HKDFExpandLabel(hashFunc, serverSecret, "iv", empty, 12)

	s.keys.handShakeKeys = &handShakeKeys{
		handShakeSecret:    handShakeSecret,
		clientSecret:       clientSecret,
		serverSecret:       serverSecret,
		clientHandShakeKey: clientHandShakeKey,
		serverHandShakeKey: serverHandShakeKey,
		clientHandShakeIV:  clientHandShakeIV,
		serverHandShakeIV:  serverHandShakeIV,
	}

	return nil
}

func (s *TLSSession) serverChangeCipherSpec() error {
	_, err := s.getRecord()
	if err != nil {
		return err
	}
	// skip change cipher spec records
	log.Debugf("Server change cipher spec")
	return nil
}

func (s *TLSSession) getRecord() (*protocol.Record, error) {
	hdr := make([]byte, protocol.RecordHeaderLen)
	_, err := io.ReadFull(s.conn, hdr)
	if err != nil {
		return nil, err
	}

	bodyLen := (int(hdr[3]) << 8) | int(hdr[4])
	body := make([]byte, bodyLen)
	_, err = io.ReadFull(s.conn, body)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	buf.Write(hdr)
	buf.Write(body)

	record := protocol.Record{}
	record.Deserialize(buf.Bytes())

	if record.Type == protocol.Record_Alert {
		alert := (record.Fragment).(*protocol.Alert).String()
		return nil, errors.New(alert)
	}

	return &record, nil
}

func (s *TLSSession) getClientHelloRecord() (*protocol.Record, error) {
	extensions := client.NewExtensions([]client.Extension{
		*client.NewExtension(
			common.Ext_ServerName,
			client.NewExtServerNameList(
				client.NewServerName(common.Host_Name, []byte(s.domain)),
			),
		),
		*client.NewExtension(
			common.Ext_SupportedGroups,
			client.NewExtSupportedGroups([]common.NamedCurve{
				common.X25519,
			}),
		),
		*client.NewExtension(
			common.Ext_SignatureAlgorithms,
			client.NewExtSignatureAlgorithms([]common.SignatureAlgorithms{
				common.ECDSA_SECP256R1_SHA256,
				common.RSA_PSS_RSAE_SHA256,
				common.RSA_PKCS1_SHA256,
				common.ECDSA_SECP384R1_SHA384,
				common.RSA_PSS_RSAE_SHA384,
				common.RSA_PKCS1_SHA384,
				common.RSA_PSS_RSAE_SHA512,
				common.RSA_PKCS1_SHA512,
				common.RSA_PKCS1_SHA1,
			}),
		),
		*client.NewExtension(
			common.Ext_KeyShare,
			client.NewExtKeyShare(
				common.X25519,
				s.keys.clientKeyPair.Public,
			),
		),
		*client.NewExtension(
			common.Ext_PSKKeyExchangeModes,
			client.NewExtPSKKeyExchangeModes([]common.PSKKeyExchangeMode{
				common.PSK_DHE_KE,
			}),
		),
		*client.NewExtension(
			common.Ext_SupportedVersions,
			client.NewExtSupportedVersions([]common.ProtocolVersion{
				common.TLS_1_3,
			}),
		),
	})

	clientHello := protocol.NewClientHello(
		common.TLS_1_2,
		crypto.Random(32),
		protocol.NewSessionID([]byte{}), // legacy field, not used
		protocol.NewCipherSuites([]common.CipherSuite{
			common.TLS_AES_128_GCM_SHA256,
		}),
		protocol.NewCompressionMethod([]byte{0}), // legacy field, not used. 0 means null
		extensions,
	)

	return protocol.NewRecord(
		protocol.Record_Handshake,
		common.TLS_1_0,
		protocol.NewHandShake(common.HandShake_ClientHello, clientHello),
	), nil
}

func openTcp(domain string) (net.Conn, error) {
	return net.Dial("tcp", withTLSPort(domain))
}

func withTLSPort(domain string) string {
	if strings.HasSuffix(domain, ":443") {
		return domain
	}
	return domain + ":443"
}
