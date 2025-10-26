package protocol

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestExtensions_Serialize(t *testing.T) {
	ext := &Extensions{
		Length: 40,
		Data: []Extension{
			{
				Type:   Ext_ServerName,
				Length: 24,
				Data: &ExtServerNameList{
					Length: 22,
					ServerName: ServerName{
						NameType: Host_Name,
						Length:   19,
						Data:     []byte("example.ulfheim.net"),
					},
				},
			},
			{
				Type:   Ext_SignatureAlgorithms,
				Length: 8,
				Data: &ExtSignatureAlgorithms{
					Length: 6,
					SignatureAlgorithms: []SignatureAlgorithms{
						ED25519,
						ED448,
						RSA_PSS_PSS_SHA256,
					},
				},
			},
		},
	}
	output := ext.Serialize()
	if !bytes.Equal(output, []byte{
		0, 40,
		0, 0, 0, 24, 0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
		46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
		0, 13, 0, 8, 0, 6, 8, 7, 8, 8, 8, 9,
	}) {
		t.Errorf("output should be %v, \ngot %v", []byte{
			0, 40,
			0, 0, 0, 24, 0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
			46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
			0, 13, 0, 8, 0, 6, 8, 7, 8, 8, 8, 9,
		}, output)
	}
}

func TestExtensions_Deserialize(t *testing.T) {
	input := []byte{
		0, 40,
		0, 0, 0, 24, 0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
		46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
		0, 13, 0, 8, 0, 6, 8, 7, 8, 8, 8, 9,
	}
	ext := &Extensions{}
	ext.Deserialize(input)

	if ext.Length != 40 {
		t.Errorf("length should be 40, \ngot %v", ext.Length)
	}
	if len(ext.Data) != 2 {
		t.Errorf("length should be 2, \ngot %v", len(ext.Data))
	}
	if ext.Data[0].Type != Ext_ServerName {
		t.Errorf("type should be Ext_ServerName, \ngot %v", ext.Data[0].Type)
	}
	if ext.Data[0].Length != 24 {
		t.Errorf("length should be 24, \ngot %v", ext.Data[0].Length)
	}

	serverNameList, ok := ext.Data[0].Data.(*ExtServerNameList)
	if !ok {
		t.Errorf("serverName should be ExtServerNameList, \ngot %v", reflect.TypeOf(serverNameList))
	}
	if serverNameList.Length != 22 {
		t.Errorf("length should be 22, \ngot %v", serverNameList.Length)
	}
	serverName := serverNameList.ServerName
	if serverName.NameType != Host_Name {
		t.Errorf("type should be Host_Name, \ngot %v", serverName.NameType)
	}
	if serverName.Length != 19 {
		t.Errorf("length should be 19, \ngot %v", serverName.Length)
	}
	if !bytes.Equal(serverName.Data, []byte("example.ulfheim.net")) {
		t.Errorf("data should be example.ulfheim.net, \ngot %v", serverName.Data)
	}

	signatureAlgorithms, ok := ext.Data[1].Data.(*ExtSignatureAlgorithms)
	if !ok {
		t.Errorf("signatureAlgorithms should be ExtSignatureAlgorithms, \ngot %v", reflect.TypeOf(signatureAlgorithms))
	}
	if signatureAlgorithms.Length != 6 {
		t.Errorf("length should be 6, \ngot %v", signatureAlgorithms.Length)
	}
	if !reflect.DeepEqual([]SignatureAlgorithms{
		ED25519,
		ED448,
		RSA_PSS_PSS_SHA256,
	}, signatureAlgorithms.SignatureAlgorithms) {
		t.Errorf("signature algorithms should be %v, \ngot %v", []SignatureAlgorithms{
			ED25519,
			ED448,
			RSA_PSS_PSS_SHA256,
		}, signatureAlgorithms.SignatureAlgorithms)
	}
}

func TestExtension_Serialize(t *testing.T) {
	ext := &Extension{
		Type:   Ext_ServerName,
		Length: 24,
		Data: &ExtServerNameList{
			Length: 22,
			ServerName: ServerName{
				NameType: Host_Name,
				Length:   19,
				Data:     []byte("example.ulfheim.net"),
			},
		},
	}
	output := ext.Serialize()

	if !bytes.Equal(output, []byte{
		0, 0, 0, 24, 0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
		46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
	}) {
		t.Errorf("output should be %v, \ngot %v", []byte{
			0, 0, 0, 24, 0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
			46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
		}, output)
	}
}

func TestExtension_Deserialize(t *testing.T) {
	input := []byte{
		0, 0, 0, 24, 0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
		46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
	}
	ext := &Extension{}
	ext.Deserialize(input)

	if ext.Type != Ext_ServerName {
		t.Errorf("type should be Ext_ServerName, \ngot %v", ext.Type)
	}
	if ext.Length != 24 {
		t.Errorf("length should be 24, \ngot %v", ext.Length)
	}

	serverNameList, ok := ext.Data.(*ExtServerNameList)
	if !ok {
		t.Errorf("Data should be ExtServerNameList, \ngot %v", reflect.TypeOf(ext.Data))
	}
	if serverNameList.Length != 22 {
		t.Errorf("length should be 22, \ngot %v", serverNameList.Length)
	}

	serverName := serverNameList.ServerName
	if serverName.NameType != Host_Name {
		t.Errorf("name type should be Host_Name, \ngot %v", serverName.NameType)
	}
	if serverName.Length != 19 {
		t.Errorf("length should be 19, \ngot %v", serverName.Length)
	}
	if !bytes.Equal(serverName.Data, []byte("example.ulfheim.net")) {
		t.Errorf("data should be example.ulfheim.net, \ngot %v", serverName.Data)
	}
}

func TestExtServerNameList_Serialize(t *testing.T) {
	ext := ExtServerNameList{
		Length: 22,
		ServerName: ServerName{
			NameType: Host_Name,
			Length:   19,
			Data:     []byte("example.ulfheim.net"),
		},
	}
	output := ext.Serialize()
	if !bytes.Equal(output, []byte{
		0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
		46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
	}) {
		t.Errorf("output should be %v, \ngot %v", []byte{
			0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
			46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
		}, output)
	}
}

func TestExtServerNameList_Deserialize(t *testing.T) {
	input := []byte{
		0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
		46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
		0, 0, 0, // redundant bytes
	}
	ext := ExtServerNameList{}
	read := ext.Deserialize(input)

	if read != 24 {
		t.Errorf("read should be %v, \ngot %v", 24, read)
	}
	if ext.Length != 22 {
		t.Errorf("length should be %v, \ngot %v", 22, ext.Length)
	}
	if ext.ServerName.NameType != Host_Name {
		t.Errorf("server name type should be %v, \ngot %v", Host_Name, ext.ServerName.NameType)
	}
	if ext.ServerName.Length != 19 {
		t.Errorf("server name length should be %v, \ngot %v", 19, ext.ServerName.Length)
	}
	if !bytes.Equal(ext.ServerName.Data, []byte("example.ulfheim.net")) {
		t.Errorf("host name should be %v, \ngot %v", []byte("example.ulfheim.net"), ext.ServerName.Data)
	}
}

func TestExtSupportedGroups_Serialize(t *testing.T) {
	ext := ExtSupportedGroups{
		Length:     2,
		NamedCurve: []NamedCurve{X25519},
	}
	output := ext.Serialize()
	if !bytes.Equal(output, []byte{0, 2, 0, 29}) {
		t.Errorf("output should be %v, \ngot %v", []byte{0, 2, 0, 29}, output)
	}
}

func TestExtSupportedGroups_Deserialize(t *testing.T) {
	input := []byte{0, 2, 0, 29, 0, 0}
	ext := ExtSupportedGroups{}
	read := ext.Deserialize(input)

	if read != 4 {
		t.Errorf("read should be %v, \ngot %v", 4, read)
	}
	if ext.Length != 2 {
		t.Errorf("length should be %v, \ngot %v", 2, ext.Length)
	}
	if len(ext.NamedCurve) != 1 {
		t.Errorf("named curve should be %v, \ngot %v", 1, len(ext.NamedCurve))
	}
	if ext.NamedCurve[0] != X25519 {
		t.Errorf("curve should be %v, \ngot %v", X25519, ext.NamedCurve[0])
	}
}

func TestExtSignatureAlgorithms_Serialize(t *testing.T) {
	ext := ExtSignatureAlgorithms{
		Length: 28,
		SignatureAlgorithms: []SignatureAlgorithms{
			ECDSA_SECP256R1_SHA256,
			ECDSA_SECP384R1_SHA384,
			ECDSA_SECP521R1_SHA512,
			ED25519,
			ED448,
			RSA_PSS_PSS_SHA256,
			RSA_PSS_PSS_SHA384,
			RSA_PSS_PSS_SHA512,
			RSA_PSS_RSAE_SHA256,
			RSA_PSS_RSAE_SHA384,
			RSA_PSS_RSAE_SHA512,
			RSA_PKCS1_SHA256,
			RSA_PKCS1_SHA384,
			RSA_PKCS1_SHA512,
		},
	}
	output := ext.Serialize()
	if !bytes.Equal(output, []byte{
		0, 28, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10,
		8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1,
	}) {
		t.Errorf("output should be %v, \ngot %v", []byte{
			0, 28, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10,
			8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1,
		}, output)
	}
}

func TestExtSignatureAlgorithms_Deserialize(t *testing.T) {
	input := []byte{
		0, 28, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10,
		8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1,
		0, 0, 0, 0, // redundant bytes
	}
	ext := ExtSignatureAlgorithms{}
	read := ext.Deserialize(input)

	if read != 30 {
		t.Errorf("read should be %v, \ngot %v", 30, read)
	}
	if ext.Length != 28 {
		t.Errorf("length should be %v, \ngot %v", 28, ext.Length)
	}
	if len(ext.SignatureAlgorithms) != 14 {
		t.Errorf("signature algorithms should be %v, \ngot %v", 14, len(ext.SignatureAlgorithms))
	}
}

func TestExtKeyShare_Serialize(t *testing.T) {
	hexStr := "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
	pubKey, _ := hex.DecodeString(hexStr)
	ext := ExtKeyShare{
		Length:      36,
		Group:       X25519,
		KeyLength:   32,
		KeyExchange: pubKey,
	}
	output := ext.Serialize()
	if !bytes.Equal(output, []byte{
		0, 36, 0, 29, 0, 32, 53, 128, 114, 214, 54, 88, 128, 209, 174, 234,
		50, 154, 223, 145, 33, 56, 56, 81, 237, 33, 162, 142, 59, 117, 233,
		101, 208, 210, 205, 22, 98, 84,
	}) {
		t.Errorf("output should be %v, \ngot %v", []byte{
			0, 36, 0, 29, 0, 32, 53, 128, 114, 214, 54, 88, 128, 209, 174, 234,
			50, 154, 223, 145, 33, 56, 56, 81, 237, 33, 162, 142, 59, 117, 233,
			101, 208, 210, 205, 22, 98, 84,
		}, output)
	}
}

func TestExtKeyShare_Deserialize(t *testing.T) {
	input := []byte{
		0, 36, 0, 29, 0, 32, 53, 128, 114, 214, 54, 88, 128, 209, 174, 234,
		50, 154, 223, 145, 33, 56, 56, 81, 237, 33, 162, 142, 59, 117, 233,
		101, 208, 210, 205, 22, 98, 84,
		0, 0, 0, 0, 0, // redundant bytes
	}
	ext := ExtKeyShare{}
	read := ext.Deserialize(input)

	if read != 38 {
		t.Errorf("read should be %v, \ngot %v", 38, read)
	}
	if ext.Length != 36 {
		t.Errorf("length should be %v, \ngot %v", 36, ext.Length)
	}
	if ext.Group != X25519 {
		t.Errorf("group should be %v, \ngot %v", X25519, ext.Group)
	}
	if ext.KeyLength != 32 {
		t.Errorf("key_length should be %v, \ngot %v", 32, ext.KeyLength)
	}
	if hex.EncodeToString(ext.KeyExchange) != "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254" {
		t.Errorf("key exchange should be %s, /ngot %v",
			"358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254",
			hex.EncodeToString(ext.KeyExchange))
	}
}

func TestExtPSKKeyExchangeModes_Serialize(t *testing.T) {
	ext := ExtPSKKeyExchangeModes{
		Length: 1,
		PSKKeyExchangeModes: []PSKKeyExchangeMode{
			PSK_DHE_KE,
		},
	}
	output := ext.Serialize()
	if !bytes.Equal(output, []byte{0x01, 0x01}) {
		t.Errorf("output should be %v, \ngot %v", []byte{0x01, 0x01}, output)
	}
}

func TestExtPSKKeyExchangeModes_Deserialize(t *testing.T) {
	input := []byte{0x01, 0x01}
	ext := ExtPSKKeyExchangeModes{}
	read := ext.Deserialize(input)
	if read != 2 {
		t.Errorf("read should be %v, \ngot %v", 2, read)
	}
	if ext.Length != 1 {
		t.Errorf("length should be %v, \ngot %v", 1, ext.Length)
	}
	if len(ext.PSKKeyExchangeModes) != 1 {
		t.Errorf("psk modes len should be %v, \ngot %v", 1, len(ext.PSKKeyExchangeModes))
	}
	if ext.PSKKeyExchangeModes[0] != PSK_DHE_KE {
		t.Errorf("PSK mode should be %v, \ngot %v", PSK_DHE_KE, ext.PSKKeyExchangeModes[0])
	}
}

func TestExtSupportedVersions_Serialize(t *testing.T) {
	ext := ExtSupportedVersions{
		Length: 2,
		SupportedVersions: []ProtocolVersion{
			TLS_1_3,
		},
	}
	output := ext.Serialize()
	if !bytes.Equal(output, []byte{0x02, 0x03, 0x04}) {
		t.Errorf("output should be %v, \ngot %v", []byte{0x02, 0x03, 0x04}, output)
	}
}

func TestExtSupportedVersions_Deserialize(t *testing.T) {
	input := []byte{0x02, 0x03, 0x04}
	ext := ExtSupportedVersions{}
	read := ext.Deserialize(input)
	if read != 3 {
		t.Errorf("read should be %v, \ngot %v", 3, read)
	}
	if ext.Length != 2 {
		t.Errorf("length should be %v, \ngot %v", 2, ext.Length)
	}
	if len(ext.SupportedVersions) != 1 {
		t.Errorf("supported versions len should be %v, \ngot %v", 1, len(ext.SupportedVersions))
	}
	if ext.SupportedVersions[0] != TLS_1_3 {
		t.Errorf("supported version should be %v, \ngot %v", TLS_1_3, ext.SupportedVersions[0])
	}
}
