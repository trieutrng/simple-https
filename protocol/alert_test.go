package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlert(t *testing.T) {
	testSuites := []struct {
		literal Alert
		bytes   []byte
	}{
		{
			literal: Alert{
				AlertLevel:       Alert_Fatal,
				AlertDescription: Alert_HandShake_Failure,
			},
			bytes: []byte{2, 40},
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
			alert := Alert{}
			read := alert.Deserialize(test.bytes)

			assert.Equal(t, len(test.bytes), read)
			assert.Equal(t, test.literal, alert)
		}
	})
}
