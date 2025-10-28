package server

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"trieutrng.com/toy-tls/common"
)

func TestExtensions(t *testing.T) {
	testSuites := []struct {
		literal Extensions
		bytes   []byte
	}{
		{
			literal: Extensions{
				Length: 18,
				Data: []Extension{
					{
						Type:   common.Ext_SupportedVersions,
						Length: 2,
						Data: &ExtSupportedVersions{
							SupportedVersion: common.TLS_1_3,
						},
					},
					{
						Type:   common.Ext_SignatureAlgorithms,
						Length: 8,
						Data: &ExtSignatureAlgorithms{
							Length: 6,
							SignatureAlgorithms: []common.SignatureAlgorithms{
								common.ED25519,
								common.ED448,
								common.RSA_PSS_PSS_SHA256,
							},
						},
					},
				},
			},
			bytes: []byte{
				0, 18,
				0, 43, 0, 2, 3, 4,
				0, 13, 0, 8, 0, 6, 8, 7, 8, 8, 8, 9,
			},
		},
	}

	t.Run("Serialize", func(t *testing.T) {
		for _, test := range testSuites {
			serialized := test.literal.Serialize()
			assert.Equal(t, test.bytes, serialized)
		}
	})

	t.Run("Deserialize", func(t *testing.T) {
		for _, test := range testSuites {
			extensions := Extensions{}
			read := extensions.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, extensions)
		}
	})
}

func TestExtension(t *testing.T) {
	testSuites := []struct {
		literal Extension
		bytes   []byte
	}{
		{
			literal: Extension{
				Type:   common.Ext_SupportedGroups,
				Length: 4,
				Data: &ExtSupportedGroups{
					Length:     2,
					NamedCurve: []common.NamedCurve{common.X25519},
				},
			},
			bytes: []byte{0, 10, 0, 4, 0, 2, 0, 29},
		},
	}

	t.Run("Serialize", func(t *testing.T) {
		for _, test := range testSuites {
			serialized := test.literal.Serialize()
			assert.Equal(t, test.bytes, serialized)
		}
	})

	t.Run("Deserialize", func(t *testing.T) {
		for _, test := range testSuites {
			extension := Extension{}
			read := extension.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, extension)
		}
	})
}

func TestExtSupportedGroups(t *testing.T) {
	testSuites := []struct {
		literal ExtSupportedGroups
		bytes   []byte
	}{
		{
			literal: ExtSupportedGroups{
				Length:     2,
				NamedCurve: []common.NamedCurve{common.X25519},
			},
			bytes: []byte{0, 2, 0, 29},
		},
	}

	t.Run("Serialize", func(t *testing.T) {
		for _, test := range testSuites {
			serialized := test.literal.Serialize()
			assert.Equal(t, test.bytes, serialized)
		}
	})

	t.Run("Deserialize", func(t *testing.T) {
		for _, test := range testSuites {
			extSupportedGroups := ExtSupportedGroups{}
			read := extSupportedGroups.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, extSupportedGroups)
		}
	})
}

func TestExtSignatureAlgorithms(t *testing.T) {
	testSuites := []struct {
		literal ExtSignatureAlgorithms
		bytes   []byte
	}{
		{
			literal: ExtSignatureAlgorithms{
				Length: 28,
				SignatureAlgorithms: []common.SignatureAlgorithms{
					common.ECDSA_SECP256R1_SHA256,
					common.ECDSA_SECP384R1_SHA384,
					common.ECDSA_SECP521R1_SHA512,
					common.ED25519,
					common.ED448,
					common.RSA_PSS_PSS_SHA256,
					common.RSA_PSS_PSS_SHA384,
					common.RSA_PSS_PSS_SHA512,
					common.RSA_PSS_RSAE_SHA256,
					common.RSA_PSS_RSAE_SHA384,
					common.RSA_PSS_RSAE_SHA512,
					common.RSA_PKCS1_SHA256,
					common.RSA_PKCS1_SHA384,
					common.RSA_PKCS1_SHA512,
				},
			},
			bytes: []byte{
				0, 28, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10,
				8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1,
			},
		},
	}

	t.Run("Serialize", func(t *testing.T) {
		for _, test := range testSuites {
			serialized := test.literal.Serialize()
			assert.Equal(t, test.bytes, serialized)
		}
	})

	t.Run("Deserialize", func(t *testing.T) {
		for _, test := range testSuites {
			extSignatureAlgorithms := ExtSignatureAlgorithms{}
			read := extSignatureAlgorithms.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, extSignatureAlgorithms)
		}
	})
}

func TestExtKeyShare(t *testing.T) {
	hexStr := "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
	pubKey, _ := hex.DecodeString(hexStr)

	testSuites := []struct {
		literal ExtKeyShare
		bytes   []byte
	}{
		{
			literal: ExtKeyShare{
				Group:       common.X25519,
				KeyLength:   32,
				KeyExchange: pubKey,
			},
			bytes: []byte{
				0, 29, 0, 32, 53, 128, 114, 214, 54, 88, 128, 209, 174, 234,
				50, 154, 223, 145, 33, 56, 56, 81, 237, 33, 162, 142, 59, 117, 233,
				101, 208, 210, 205, 22, 98, 84,
			},
		},
	}

	t.Run("Serialize", func(t *testing.T) {
		for _, test := range testSuites {
			serialized := test.literal.Serialize()
			assert.Equal(t, test.bytes, serialized)
		}
	})

	t.Run("Deserialize", func(t *testing.T) {
		for _, test := range testSuites {
			extKeyShare := ExtKeyShare{}
			read := extKeyShare.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, extKeyShare)
		}
	})
}

func TestExtSupportedVersions(t *testing.T) {
	testSuites := []struct {
		literal ExtSupportedVersions
		bytes   []byte
	}{
		{
			literal: ExtSupportedVersions{
				SupportedVersion: common.TLS_1_3,
			},
			bytes: []byte{0x03, 0x04},
		},
	}

	t.Run("Serialize", func(t *testing.T) {
		for _, test := range testSuites {
			serialized := test.literal.Serialize()
			assert.Equal(t, test.bytes, serialized)
		}
	})

	t.Run("Deserialize", func(t *testing.T) {
		for _, test := range testSuites {
			extSupportedVersions := ExtSupportedVersions{}
			read := extSupportedVersions.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, extSupportedVersions)
		}
	})
}
