package session

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"trieutrng.com/toy-tls/crypto"
	"trieutrng.com/toy-tls/protocol"
)

type TLSSession struct {
	conn            net.Conn
	sessionKey      []byte
	domain          string
	keyPair         *crypto.KeyPair
	serverPublicKey []byte
}

func NewSession(domain string) (*TLSSession, error) {
	conn, err := openTcp(domain)
	if err != nil {
		return nil, err
	}

	tlsSession := &TLSSession{
		conn:   conn,
		domain: domain,
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
	return nil
}

func (s *TLSSession) generateKeyExchange() error {
	keyPair, err := crypto.GetX25519KeyPair()
	if err != nil {
		return err
	}
	s.keyPair = keyPair
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

	fmt.Printf("Server chosen cipher suite: %v", serverHello.CipherSuite)

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
	extensions := protocol.NewExtensions([]protocol.Extension{
		*protocol.NewExtension(
			protocol.Ext_ServerName,
			protocol.NewExtServerNameList(
				protocol.NewServerName(protocol.Host_Name, []byte(s.domain)),
			),
		),
		*protocol.NewExtension(
			protocol.Ext_SupportedGroups,
			protocol.NewExtSupportedGroups([]protocol.NamedCurve{
				protocol.X25519,
			}),
		),
		*protocol.NewExtension(
			protocol.Ext_SignatureAlgorithms,
			protocol.NewExtSignatureAlgorithms([]protocol.SignatureAlgorithms{
				protocol.ECDSA_SECP256R1_SHA256,
				protocol.RSA_PSS_RSAE_SHA256,
				protocol.RSA_PKCS1_SHA256,
				protocol.ECDSA_SECP384R1_SHA384,
				protocol.RSA_PSS_RSAE_SHA384,
				protocol.RSA_PKCS1_SHA384,
				protocol.RSA_PSS_RSAE_SHA512,
				protocol.RSA_PKCS1_SHA512,
				protocol.RSA_PKCS1_SHA1,
			}),
		),
		*protocol.NewExtension(
			protocol.Ext_KeyShare,
			protocol.NewExtKeyShare(
				protocol.X25519,
				s.keyPair.Public,
			),
		),
		*protocol.NewExtension(
			protocol.Ext_PSKKeyExchangeModes,
			protocol.NewExtPSKKeyExchangeModes([]protocol.PSKKeyExchangeMode{
				protocol.PSK_DHE_KE,
			}),
		),
		*protocol.NewExtension(
			protocol.Ext_SupportedVersions,
			protocol.NewExtSupportedVersions([]protocol.ProtocolVersion{
				protocol.TLS_1_3,
			}),
		),
	})

	clientHello := protocol.NewClientHello(
		protocol.TLS_1_2,
		crypto.Random(32),
		protocol.NewSessionID([]byte{}), // legacy field, not used
		protocol.NewCipherSuites([]protocol.CipherSuite{
			protocol.TLS_AES_128_GCM_SHA256,
		}),
		protocol.NewCompressionMethod([]byte{0}), // legacy field, not used. 0 means null
		extensions,
	)

	return protocol.NewRecord(
		protocol.Record_Handshake,
		protocol.TLS_1_0,
		protocol.NewHandShake(protocol.HandShake_ClientHello, clientHello),
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
