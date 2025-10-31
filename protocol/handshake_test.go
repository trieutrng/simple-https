package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"trieutrng.com/toy-tls/common"
	"trieutrng.com/toy-tls/protocol/client"
	"trieutrng.com/toy-tls/protocol/server"
)

func TestHandShake(t *testing.T) {
	testSuites := []struct {
		literal HandShake
		bytes   []byte
	}{
		{
			literal: HandShake{
				Type:   common.HandShake_ClientHello,
				Length: 121,
				Body: &ClientHello{
					ProtocolVersion: common.TLS_1_2,
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
						CipherSuites: []common.CipherSuite{
							common.TLS_AES_256_GCM_SHA384,
							common.TLS_CHACHA20_POLY1305_SHA256,
							common.TLS_AES_128_GCM_SHA256,
							common.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
						},
					},
					LegacyCompressionMethods: CompressionMethod{
						Length: 1,
						Data:   []byte{0}, // 0 == null
					},
					Extensions: client.Extensions{
						Length: 40,
						Data: []client.Extension{
							{
								Type:   common.Ext_ServerName,
								Length: 24,
								Data: &client.ExtServerNameList{
									Length: 22,
									ServerName: client.ServerName{
										NameType: common.Host_Name,
										Length:   19,
										Data:     []byte("example.ulfheim.net"),
									},
								},
							},
							{
								Type:   common.Ext_SignatureAlgorithms,
								Length: 8,
								Data: &client.ExtSignatureAlgorithms{
									Length: 6,
									SignatureAlgorithms: []common.SignatureAlgorithm{
										common.ED25519,
										common.ED448,
										common.RSA_PSS_PSS_SHA256,
									},
								},
							},
						},
					},
				},
			},

			bytes: []byte{
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
				0, 8, 19, 2, 19, 3, 19, 1, 0, 255,
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
			handShake := HandShake{}
			read := handShake.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, handShake)
		}
	})
}

func TestClientHello(t *testing.T) {
	testSuites := []struct {
		literal ClientHello
		bytes   []byte
	}{
		{
			literal: ClientHello{
				ProtocolVersion: common.TLS_1_2,
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
					CipherSuites: []common.CipherSuite{
						common.TLS_AES_256_GCM_SHA384,
						common.TLS_CHACHA20_POLY1305_SHA256,
						common.TLS_AES_128_GCM_SHA256,
						common.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
					},
				},
				LegacyCompressionMethods: CompressionMethod{
					Length: 1,
					Data:   []byte{0}, // 0 == null
				},
				Extensions: client.Extensions{
					Length: 40,
					Data: []client.Extension{
						{
							Type:   common.Ext_ServerName,
							Length: 24,
							Data: &client.ExtServerNameList{
								Length: 22,
								ServerName: client.ServerName{
									NameType: common.Host_Name,
									Length:   19,
									Data:     []byte("example.ulfheim.net"),
								},
							},
						},
						{
							Type:   common.Ext_SignatureAlgorithms,
							Length: 8,
							Data: &client.ExtSignatureAlgorithms{
								Length: 6,
								SignatureAlgorithms: []common.SignatureAlgorithm{
									common.ED25519,
									common.ED448,
									common.RSA_PSS_PSS_SHA256,
								},
							},
						},
					},
				},
			},
			bytes: []byte{
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
				0, 8, 19, 2, 19, 3, 19, 1, 0, 255,
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
			clientHello := ClientHello{}
			read := clientHello.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, clientHello)
		}
	})
}

func TestServerHello(t *testing.T) {
	testSuites := []struct {
		literal ServerHello
		bytes   []byte
	}{
		{
			literal: ServerHello{
				ProtocolVersion: common.TLS_1_2,
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
				CipherSuite:             common.TLS_AES_128_GCM_SHA256,
				LegacyCompressionMethod: 0,
				Extensions: server.Extensions{
					Length: 18,
					Data: []server.Extension{
						{
							Type:   common.Ext_SupportedVersions,
							Length: 2,
							Data: &server.ExtSupportedVersions{
								SupportedVersion: common.TLS_1_3,
							},
						},
						{
							Type:   common.Ext_SignatureAlgorithms,
							Length: 8,
							Data: &server.ExtSignatureAlgorithms{
								Length: 6,
								SignatureAlgorithms: []common.SignatureAlgorithm{
									common.ED25519,
									common.ED448,
									common.RSA_PSS_PSS_SHA256,
								},
							},
						},
					},
				},
			},
			bytes: []byte{
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
				// cipher suite
				19, 1,
				// legacy compression method
				0,
				// extensions
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
			serverHello := ServerHello{}
			read := serverHello.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, serverHello)
		}
	})
}

func TestSessionID(t *testing.T) {
	testSuites := []struct {
		literal SessionID
		bytes   []byte
	}{
		{
			literal: SessionID{
				Length: 32,
				Data: []byte{224, 225, 226, 227, 228, 229, 230,
					231, 232, 233, 234, 235, 236, 237, 238,
					239, 240, 241, 242, 243, 244, 245, 246,
					247, 248, 249, 250, 251, 252, 253, 254, 255,
				},
			},
			bytes: []byte{32, 224, 225, 226, 227, 228, 229, 230,
				231, 232, 233, 234, 235, 236, 237, 238,
				239, 240, 241, 242, 243, 244, 245, 246,
				247, 248, 249, 250, 251, 252, 253, 254, 255,
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
			sessionID := SessionID{}
			read := sessionID.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, sessionID)
		}
	})
}

func TestCipherSuites(t *testing.T) {
	testSuites := []struct {
		literal CipherSuites
		bytes   []byte
	}{
		{
			literal: CipherSuites{
				Length: 8,
				CipherSuites: []common.CipherSuite{
					common.TLS_AES_256_GCM_SHA384,
					common.TLS_CHACHA20_POLY1305_SHA256,
					common.TLS_AES_128_GCM_SHA256,
					common.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
				},
			},
			bytes: []byte{0, 8, 19, 2, 19, 3, 19, 1, 0, 255},
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
			cipherSuites := CipherSuites{}
			read := cipherSuites.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, cipherSuites)
		}
	})
}

func TestCompressionMethod(t *testing.T) {
	testSuites := []struct {
		literal CompressionMethod
		bytes   []byte
	}{
		{
			literal: CompressionMethod{
				Length: 1,
				Data:   []byte{0}, // 0 == null
			},
			bytes: []byte{1, 0},
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
			compressionMethod := CompressionMethod{}
			read := compressionMethod.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, compressionMethod)
		}
	})
}
