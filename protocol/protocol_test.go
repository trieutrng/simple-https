package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecord(t *testing.T) {
	testSuites := []struct {
		literal Record
		bytes   []byte
	}{
		{
			literal: Record{
				Type:            Record_Handshake,
				ProtocolVersion: TLS_1_0,
				Length:          125,
				Fragment: &HandShake{
					Type:   HandShake_ClientHello,
					Length: 121,
					Body: &ClientHello{
						ProtocolVersion: TLS_1_2,
						Random: []byte{
							0, 1, 2, 3, 4, 5, 6, 7,
							8, 9, 10, 11, 12, 13, 14, 15,
							16, 17, 18, 19, 20, 21, 22, 23,
							24, 25, 26, 27, 28, 29, 30, 31,
						},
						LegacySessionId: SessionID{
							Length: 32,
							Data: []byte{224, 225, 226, 227, 228, 229, 230,
								231, 232, 233, 234, 235, 236, 237, 238,
								239, 240, 241, 242, 243, 244, 245, 246,
								247, 248, 249, 250, 251, 252, 253, 254, 255,
							},
						},
						CipherSuites: CipherSuites{
							Length: 8,
							CipherSuites: []CipherSuite{
								TLS_AES_256_GCM_SHA384,
								TLS_CHACHA20_POLY1305_SHA256,
								TLS_AES_128_GCM_SHA256,
								TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
							},
						},
						LegacyCompressionMethods: CompressionMethod{
							Length: 1,
							Data:   []byte{0}, // 0 == null
						},
						Extensions: Extensions{
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
						},
					},
				},
			},

			bytes: []byte{
				// record type
				22,
				// protocol version
				3, 1,
				// length
				0, 125,
				// handshake message type
				1,
				// client hello length
				0, 0, 121,
				// protocol version
				3, 3,
				// random
				0, 1, 2, 3, 4, 5, 6, 7,
				8, 9, 10, 11, 12, 13, 14, 15,
				16, 17, 18, 19, 20, 21, 22, 23,
				24, 25, 26, 27, 28, 29, 30, 31,
				// legacy session id
				32, 224, 225, 226, 227, 228, 229, 230,
				231, 232, 233, 234, 235, 236, 237, 238,
				239, 240, 241, 242, 243, 244, 245, 246,
				247, 248, 249, 250, 251, 252, 253, 254, 255,
				// cipher suites
				0, 8, 13, 2, 13, 3, 13, 1, 0, 255,
				// legacy compression method
				1, 0,
				// extensions
				0, 40,
				0, 0, 0, 24, 0, 22, 0, 0, 19, 101, 120, 97, 109, 112, 108, 101,
				46, 117, 108, 102, 104, 101, 105, 109, 46, 110, 101, 116,
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
			record := Record{}
			read := record.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, record)
		}
	})
}
