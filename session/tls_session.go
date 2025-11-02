package session

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"trieutrng.com/toy-tls/common"
	"trieutrng.com/toy-tls/crypto"
	"trieutrng.com/toy-tls/helpers"
	"trieutrng.com/toy-tls/protocol"
	"trieutrng.com/toy-tls/protocol/client"
	"trieutrng.com/toy-tls/protocol/server"
)

type TLSSession struct {
	conn          net.Conn
	domain        string
	keys          *keys
	msgForKeyCalc []*protocol.HandShake
	hashFunc      func() hash.Hash
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
	decryptedRecords   byte
}

type applicationKeys struct {
	clientApplicationKey []byte
	serverApplicationKey []byte
	clientApplicationIV  []byte // initialization vector
	serverApplicationIV  []byte // initialization vector
	receivedRecords      byte
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

func (s *TLSSession) Write(content []byte) error {
	encryptedRecord, err := s.encryptApplicationData(content)
	if err != nil {
		log.Error("failed to encrypt application data")
		return err
	}
	n, err := s.conn.Write(encryptedRecord)
	if err != nil {
		return err
	}
	log.Debugf("wrote %d bytes of encrypted messages", n)
	return nil
}

func (s *TLSSession) Read() ([]byte, error) {
	var msg *protocol.ApplicationData

	for {
		record, err := s.getDecryptedApplicationMessage()
		if err != nil {
			log.Error("failed to read application data")
			return nil, err
		}
		handShake, ok := (record).(*protocol.HandShake)
		if ok && handShake.Type == common.HandShake_NewSessionTicket {
			log.Debugf("received new session ticket: \n\t%v", handShake.Body)
			// skip session ticket for now
			continue
		}
		msg = record.(*protocol.ApplicationData)
		break
	}

	return msg.Content, nil
}

func (s *TLSSession) handShake() error {
	if err := s.generateKeyExchange(); err != nil {
		log.Errorf("Failed on step generate key pair: %v", err)
		return err
	}
	if err := s.clientHello(); err != nil {
		log.Errorf("Failed on step sending client hello: %v", err)
		return err
	}
	if err := s.serverHello(); err != nil {
		log.Errorf("Failed on step receiving server hello: %v", err)
		return err
	}
	if err := s.calculateHandshakeKeys(); err != nil {
		log.Errorf("Failed on step calculating handshake keys: %v", err)
		return err
	}
	if err := s.getServerChangeCipherSpec(); err != nil {
		log.Errorf("Failed on step getting server change cipher spec: %v", err)
		return err
	}
	if err := s.getServerEncryptedExtensions(); err != nil {
		log.Errorf("Failed on step getting server encrypted extensions: %v", err)
		return err
	}
	if err := s.getServerCertificate(); err != nil {
		log.Errorf("Failed on step getting server certificate: %v", err)
		return err
	}
	if err := s.verifyServerCertificate(); err != nil {
		log.Errorf("Failed on step verifying server certificate: %v", err)
		return err
	}
	if err := s.verifyHandShakeFinished(); err != nil {
		log.Errorf("Failed on step verifying handshake finished: %v", err)
		return err
	}
	if err := s.calculateApplicationKeys(); err != nil {
		log.Errorf("Failed on step calculating application keys: %v", err)
		return err
	}
	if err := s.sendChangeCipherSpec(); err != nil {
		log.Errorf("Failed on step sending client change cipher spec: %v", err)
		return err
	}
	if err := s.sendClientHandShakeFinished(); err != nil {
		log.Errorf("Failed on step sending client handshake finished: %v", err)
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

	s.msgForKeyCalc = append(s.msgForKeyCalc, (record.Fragment).(*protocol.HandShake))
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

	s.msgForKeyCalc = append(s.msgForKeyCalc, (record.Fragment).(*protocol.HandShake))

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
	s.hashFunc = sha256.New

	return nil
}

func (s *TLSSession) calculateHandshakeKeys() error {
	// calculate shared secret
	sharedSecret, err := crypto.GetSharedSecretX25519(s.keys.clientKeyPair.Private, s.keys.serverPublicKey)
	if err != nil {
		return err
	}

	// calculate handshake keys
	// use sha256 hash func here since the server and client has been accepted on cipher suite with SHA256
	hashLength := sha256.Size
	hashMessage := func(message []byte) []byte {
		hashedMessage := sha256.Sum256(message)
		return hashedMessage[:]
	}

	// concatenate hello records (clientHello + serverHello)
	concatenatedHello := make([]byte, 0)
	for _, msg := range s.msgForKeyCalc {
		concatenatedHello = append(concatenatedHello, msg.Serialize()...)
	}
	// hash concatenation
	hashedHello := hashMessage(concatenatedHello)

	var empty []byte
	zeroSalt := make([]byte, 32)
	zeroSecret := make([]byte, 32)

	earlySecret := crypto.HKDFExtract(s.hashFunc, zeroSecret, zeroSalt)
	derivedSecret := crypto.HKDFExpandLabel(s.hashFunc, earlySecret, "derived", hashMessage(empty), hashLength)
	handShakeSecret := crypto.HKDFExtract(s.hashFunc, sharedSecret, derivedSecret)

	clientSecret := crypto.HKDFExpandLabel(s.hashFunc, handShakeSecret, "c hs traffic", hashedHello, hashLength)
	clientHandShakeKey := crypto.HKDFExpandLabel(s.hashFunc, clientSecret, "key", empty, 16)
	clientHandShakeIV := crypto.HKDFExpandLabel(s.hashFunc, clientSecret, "iv", empty, 12)

	serverSecret := crypto.HKDFExpandLabel(s.hashFunc, handShakeSecret, "s hs traffic", hashedHello, hashLength)
	serverHandShakeKey := crypto.HKDFExpandLabel(s.hashFunc, serverSecret, "key", empty, 16)
	serverHandShakeIV := crypto.HKDFExpandLabel(s.hashFunc, serverSecret, "iv", empty, 12)

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

func (s *TLSSession) getServerChangeCipherSpec() error {
	_, err := s.getRecord()
	if err != nil {
		return err
	}
	// skip change cipher spec records
	log.Debugf("Server change cipher spec")
	return nil
}

func (s *TLSSession) getServerEncryptedExtensions() error {
	fragment, err := s.getDecryptedHandShakeMessage()
	if err != nil {
		return errors.New("can't decrypt server encrypted extensions - Caused by: " + err.Error())
	}
	handShake, ok := (fragment).(*protocol.HandShake)
	if !ok {
		return errors.New("failed on casting handshake message")
	}
	log.Debugf("Server encrypted extensions: %v", handShake.Body.Serialize())
	return nil
}

func (s *TLSSession) getServerCertificate() error {
	fragment, err := s.getDecryptedHandShakeMessage()
	if err != nil {
		return errors.New("can't decrypt server certificate - Caused by: " + err.Error())
	}
	handShake, ok := (fragment).(*protocol.HandShake)
	if !ok {
		return errors.New("failed on casting handshake message")
	}
	certificate, ok := (handShake.Body).(*protocol.Certificate)
	if !ok {
		return errors.New("failed on casting certificate message")
	}
	log.Debugf("Server certificate: %v", certificate.Serialize())
	return nil
}

func (s *TLSSession) verifyServerCertificate() error {
	fragment, err := s.getDecryptedHandShakeMessage()
	if err != nil {
		return errors.New("can't decrypt server certificate - Caused by: " + err.Error())
	}
	handShake, ok := (fragment).(*protocol.HandShake)
	if !ok {
		return errors.New("failed on casting handshake message")
	}
	certificateVerify, ok := (handShake.Body).(*protocol.CertificateVerify)
	if !ok {
		return errors.New("failed on casting certificate verify message")
	}
	log.Debugf("Server certificate verify signature algorithm: %v, len: %d", certificateVerify.SignatureAlgorithm, certificateVerify.Length)

	// TODO: verify cert with root CA

	return nil
}

func (s *TLSSession) verifyHandShakeFinished() error {
	fragment, err := s.getDecryptedHandShakeMessage()
	if err != nil {
		return errors.New("can't decrypt server certificate - Caused by: " + err.Error())
	}
	handShake, ok := (fragment).(*protocol.HandShake)
	if !ok {
		return errors.New("failed on casting handshake message")
	}
	handShakeFinished, ok := (handShake.Body).(*protocol.HandShakeFinished)
	if !ok {
		return errors.New("failed on casting handshake finished message")
	}
	log.Debugf("Server handshake finished hash verifier: %v", handShakeFinished.HashedVerifier)

	// calculate handshake hash
	hashLength := sha256.Size
	hashMessage := func(message []byte) []byte {
		hashedMessage := sha256.Sum256(message)
		return hashedMessage[:]
	}

	// concatenate hello records
	concatenatedHandShake := make([]byte, 0)
	// get rid of server handshake finished
	msgCount := len(s.msgForKeyCalc) - 1
	for _, msg := range s.msgForKeyCalc[:msgCount] {
		concatenatedHandShake = append(concatenatedHandShake, msg.Serialize()...)
	}

	hashedHandShake := hashMessage(concatenatedHandShake)
	finishedKey := crypto.HKDFExpandLabel(s.hashFunc, s.keys.handShakeKeys.serverSecret, "finished", []byte{}, hashLength)

	if ok := crypto.VerifyHMACSHA256(finishedKey, hashedHandShake, handShakeFinished.HashedVerifier); !ok {
		return errors.New("finished hash verification failed")
	}

	return nil
}

func (s *TLSSession) calculateApplicationKeys() error {
	// calculate handshake keys
	// use sha256 hash func here since the server and client has been accepted on cipher suite with SHA256
	hashLength := sha256.Size
	hashMessage := func(message []byte) []byte {
		hashedMessage := sha256.Sum256(message)
		return hashedMessage[:]
	}

	// concatenate hello records (clientHello, serverHello, ...)
	concatenatedHandShake := make([]byte, 0)
	for _, msg := range s.msgForKeyCalc {
		concatenatedHandShake = append(concatenatedHandShake, msg.Serialize()...)
	}
	// hash concatenation
	hashedHandShake := hashMessage(concatenatedHandShake)

	var empty []byte
	zeroSecret := make([]byte, 32)

	derivedSecret := crypto.HKDFExpandLabel(s.hashFunc, s.keys.handShakeKeys.handShakeSecret, "derived", hashMessage(empty), hashLength)
	masterSecret := crypto.HKDFExtract(s.hashFunc, zeroSecret, derivedSecret)

	clientSecret := crypto.HKDFExpandLabel(s.hashFunc, masterSecret, "c ap traffic", hashedHandShake, hashLength)
	clientApplicationKey := crypto.HKDFExpandLabel(s.hashFunc, clientSecret, "key", empty, 16)
	clientApplicationIV := crypto.HKDFExpandLabel(s.hashFunc, clientSecret, "iv", empty, 12)

	serverSecret := crypto.HKDFExpandLabel(s.hashFunc, masterSecret, "s ap traffic", hashedHandShake, hashLength)
	serverApplicationKey := crypto.HKDFExpandLabel(s.hashFunc, serverSecret, "key", empty, 16)
	serverApplicationIV := crypto.HKDFExpandLabel(s.hashFunc, serverSecret, "iv", empty, 12)

	s.keys.applicationKeys = &applicationKeys{
		clientApplicationKey: clientApplicationKey,
		clientApplicationIV:  clientApplicationIV,
		serverApplicationKey: serverApplicationKey,
		serverApplicationIV:  serverApplicationIV,
	}

	return nil
}

func (s *TLSSession) sendChangeCipherSpec() error {
	record := protocol.NewRecord(
		protocol.Record_ChangeCipherSpec,
		common.TLS_1_2,
		protocol.NewChangeCipherSpec(1),
	)
	n, err := s.conn.Write(record.Serialize())
	if err != nil {
		return err
	}
	log.Debugf("Exchanged %v bytes of client change cipher spec", n)
	return nil
}

func (s *TLSSession) sendClientHandShakeFinished() error {
	// calculate verify data
	hashLength := sha256.Size
	hashMessage := func(message []byte) []byte {
		hashedMessage := sha256.Sum256(message)
		return hashedMessage[:]
	}
	// concatenate hello records
	concatenatedHandShake := make([]byte, 0)
	// get rid of server handshake finished
	for _, msg := range s.msgForKeyCalc {
		concatenatedHandShake = append(concatenatedHandShake, msg.Serialize()...)
	}

	hashedHandShake := hashMessage(concatenatedHandShake)
	finishedKey := crypto.HKDFExpandLabel(s.hashFunc, s.keys.handShakeKeys.clientSecret, "finished", []byte{}, hashLength)
	verifier := crypto.ComputeHMACSHA256(finishedKey, hashedHandShake)

	handShakeFinished := protocol.NewHandShake(
		common.HandShake_Finished,
		protocol.NewHandShakeFinished(verifier),
	)

	// last byte indicates record type
	plainText := handShakeFinished.Serialize()
	plainText = append(plainText, byte(protocol.Record_Handshake))

	// encrypt handshake finished
	additionalData := make([]byte, 0)
	additionalData = append(additionalData, byte(protocol.Record_ApplicationData))
	additionalData = append(additionalData, helpers.Uint16ToBytes(uint16(common.TLS_1_2))...)
	additionalData = append(additionalData, []byte{0x00, 0x35}...) // len: 53

	cipherText := crypto.AESGCMEncrypt(s.keys.handShakeKeys.clientHandShakeKey, s.keys.handShakeKeys.clientHandShakeIV, plainText, additionalData)

	record := protocol.NewRecord(
		protocol.Record_ApplicationData,
		common.TLS_1_2,
		protocol.NewApplicationData(cipherText),
	)

	n, err := s.conn.Write(record.Serialize())
	if err != nil {
		return err
	}
	log.Debugf("Exchanged %v bytes of sending client handshake finished", n)
	return nil
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
			client.NewExtSignatureAlgorithms([]common.SignatureAlgorithm{
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

func (s *TLSSession) getDecryptedHandShakeMessage() (common.ExchangeObject, error) {
	record, err := s.getRecord()
	if err != nil {
		return nil, err
	}

	// every upcoming record would be encrypted with IV XOR'ed with incremental number
	// for the purpose of making identical messages have same encryption
	lenIV := len(s.keys.handShakeKeys.serverHandShakeIV)
	XORedIV := make([]byte, lenIV)
	copy(XORedIV, s.keys.handShakeKeys.serverHandShakeIV)
	XORedIV[lenIV-1] ^= s.keys.handShakeKeys.decryptedRecords

	payload := crypto.AESGCMDecrypt(s.keys.handShakeKeys.serverHandShakeKey, XORedIV, record.Serialize())

	s.keys.handShakeKeys.decryptedRecords++
	bound := len(payload) - 1

	// get rid of zeros which is optional padding in RFC8446
	// https://datatracker.ietf.org/doc/html/rfc8446#autoid-60
	for bound >= 0 && payload[bound] == 0 {
		bound--
	}
	if bound < 0 {
		return nil, errors.New("can't get content type")
	}

	decryptedContentType := protocol.ContentType(payload[bound])
	fragment := protocol.NewFragment(decryptedContentType)
	fragment.Deserialize(payload[:bound])

	// store handshake records for keys calculation
	s.msgForKeyCalc = append(s.msgForKeyCalc, (fragment).(*protocol.HandShake))

	return fragment, nil
}

func (s *TLSSession) getDecryptedApplicationMessage() (common.ExchangeObject, error) {
	record, err := s.getRecord()
	if err != nil {
		return nil, err
	}

	// every upcoming record would be encrypted with IV XOR'ed with incremental number
	// for the purpose of making identical messages have same encryption
	lenIV := len(s.keys.applicationKeys.serverApplicationIV)
	XORedIV := make([]byte, lenIV)
	copy(XORedIV, s.keys.applicationKeys.serverApplicationIV)
	XORedIV[lenIV-1] ^= s.keys.applicationKeys.receivedRecords

	payload := crypto.AESGCMDecrypt(s.keys.applicationKeys.serverApplicationKey, XORedIV, record.Serialize())

	s.keys.applicationKeys.receivedRecords++
	bound := len(payload) - 1

	// get rid of zeros which is optional padding in RFC8446
	// https://datatracker.ietf.org/doc/html/rfc8446#autoid-60
	for bound >= 0 && payload[bound] == 0 {
		bound--
	}
	if bound < 0 {
		return nil, errors.New("can't get content type")
	}

	decryptedContentType := protocol.ContentType(payload[bound])
	fragment := protocol.NewFragment(decryptedContentType)
	fragment.Deserialize(payload[:bound])

	if _, ok := (fragment).(*protocol.Alert); ok {
		alert := (fragment).(*protocol.Alert).String()
		return nil, errors.New(alert)
	}

	return fragment, nil
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

func (s *TLSSession) encryptApplicationData(content []byte) ([]byte, error) {
	appData := protocol.NewApplicationData(content)
	plainText := appData.Serialize()
	plainText = append(plainText, byte(protocol.Record_ApplicationData))

	// encrypt handshake finished
	additionalData := make([]byte, 0)
	additionalData = append(additionalData, byte(protocol.Record_ApplicationData))
	additionalData = append(additionalData, helpers.Uint16ToBytes(uint16(common.TLS_1_2))...)
	additionalData = append(additionalData, helpers.Uint16ToBytes(uint16(len(plainText)+16))...) // 16 as auth tag

	cipherText := crypto.AESGCMEncrypt(s.keys.applicationKeys.clientApplicationKey, s.keys.applicationKeys.clientApplicationIV, plainText, additionalData)

	record := protocol.NewRecord(
		protocol.Record_ApplicationData,
		common.TLS_1_2,
		protocol.NewApplicationData(cipherText),
	)

	return record.Serialize(), nil
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
