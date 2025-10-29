package session

import (
	"bytes"
	"errors"
	"fmt"
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
	conn    net.Conn
	domain  string
	keys    *keys
	records []*protocol.Record
}

type keys struct {
	clientKeyPair   *crypto.KeyPair
	serverPublicKey []byte
	sessionKey      []byte
	handShakeKeys   handShakeKeys
	applicationKeys applicationKeys
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
		log.Errorf("Failed to calculate session keys: %v", err)
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

	fmt.Printf("Server chosen cipher suite: %v\n", serverHello.CipherSuite)
	fmt.Printf("Server returned %d extensions\n", len(serverHello.Extensions.Data))
	fmt.Println("Extensions:")

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
	return nil // TODO
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
