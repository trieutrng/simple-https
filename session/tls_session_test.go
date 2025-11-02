package session

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"trieutrng.com/toy-tls/crypto"
	"trieutrng.com/toy-tls/protocol"
)

func TestCalculateHandShakeKeys(t *testing.T) {
	// given
	clientPrivateKey, _ := hex.DecodeString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	serverPublicKey, _ := hex.DecodeString("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615")

	clientHello, _ := hex.DecodeString("16030100ca010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304")
	clientHelloRecord := &protocol.Record{}
	clientHelloRecord.Deserialize(clientHello)

	serverHello, _ := hex.DecodeString("160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304")
	serverHelloRecord := &protocol.Record{}
	serverHelloRecord.Deserialize(serverHello)

	s := TLSSession{
		keys: &keys{
			clientKeyPair: &crypto.KeyPair{
				Private: clientPrivateKey,
			},
			serverPublicKey: serverPublicKey,
		},
		msgForKeyCalc: []*protocol.HandShake{
			(clientHelloRecord.Fragment).(*protocol.HandShake),
			(serverHelloRecord.Fragment).(*protocol.HandShake),
		},
		hashFunc: sha256.New,
	}

	// when
	err := s.calculateHandshakeKeys()
	if err != nil {
		t.Fatal(err)
	}

	// then
	assert.Equal(t, hex.EncodeToString(s.keys.handShakeKeys.handShakeSecret), "fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a")
	assert.Equal(t, hex.EncodeToString(s.keys.handShakeKeys.clientSecret), "ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea")
	assert.Equal(t, hex.EncodeToString(s.keys.handShakeKeys.serverSecret), "a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814")
	assert.Equal(t, hex.EncodeToString(s.keys.handShakeKeys.serverHandShakeIV), "4c042ddc120a38d1417fc815")
	assert.Equal(t, hex.EncodeToString(s.keys.handShakeKeys.clientHandShakeKey), "7154f314e6be7dc008df2c832baa1d39")
	assert.Equal(t, hex.EncodeToString(s.keys.handShakeKeys.serverHandShakeKey), "844780a7acad9f980fa25c114e43402a")
	assert.Equal(t, hex.EncodeToString(s.keys.handShakeKeys.clientHandShakeIV), "71abc2cae4c699d47c600268")
	assert.Equal(t, hex.EncodeToString(s.keys.handShakeKeys.serverHandShakeIV), "4c042ddc120a38d1417fc815")
}
