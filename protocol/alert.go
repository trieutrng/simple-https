package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"

	log "github.com/sirupsen/logrus"
)

type AlertLevel uint8

const (
	Alert_Warning AlertLevel = 1
	Alert_Fatal   AlertLevel = 2
)

type AlertDescription uint8

const (
	Alert_Close_Notify                    AlertDescription = 0
	Alert_Unexpected_message              AlertDescription = 0xa
	Alert_Bad_Record_Mac                  AlertDescription = 0x14
	Alert_Record_Overflow                 AlertDescription = 0x16
	Alert_HandShake_Failure               AlertDescription = 0x28
	Alert_Bad_Certificate                 AlertDescription = 0x2a
	Alert_Unsupported_Certificate         AlertDescription = 0x2b
	Alert_Certificate_Revoked             AlertDescription = 0x2c
	Alert_Certificate_Expired             AlertDescription = 0x2d
	Alert_Certificate_Unknown             AlertDescription = 0x2e
	Alert_Illegal_Parameters              AlertDescription = 0x2f
	Alert_Unknown_Call                    AlertDescription = 0x30
	Alert_Access_Denied                   AlertDescription = 0x31
	Alert_Decode_Error                    AlertDescription = 0x32
	Alert_Decrypt_Error                   AlertDescription = 0x33
	Alert_Protocol_Version                AlertDescription = 0x46
	Alert_Insufficient_Security           AlertDescription = 0x47
	Alert_Internal_Error                  AlertDescription = 0x50
	Alert_Inappropriate_Fallback          AlertDescription = 0x56
	Alert_User_Canceled                   AlertDescription = 0x5a
	Alert_Missing_Extension               AlertDescription = 0x6d
	Alert_Unsupported_Extension           AlertDescription = 0x6e
	Alert_Unrecognized_Name               AlertDescription = 0x70
	Alert_Bad_Certificate_Status_Response AlertDescription = 0x71
	Alert_Unknow_PSK_Identity             AlertDescription = 0x73
	Alert_Ceritificate_Required           AlertDescription = 0x74
	Alert_No_Application_Protocol         AlertDescription = 0x78
)

var alertLevelMap map[AlertLevel]string
var alertDescriptionMap map[AlertDescription]string

func init() {
	log.Debugf("Initializing alert description map")

	alertLevelMap = make(map[AlertLevel]string)
	alertLevelMap[Alert_Warning] = "Warning"
	alertLevelMap[Alert_Fatal] = "Fatal"

	alertDescriptionMap = make(map[AlertDescription]string)
	alertDescriptionMap[Alert_Close_Notify] = "Close Notify"
	alertDescriptionMap[Alert_Unexpected_message] = "Unexpected message"
	alertDescriptionMap[Alert_Bad_Record_Mac] = "Bad record mac"
	alertDescriptionMap[Alert_Record_Overflow] = "Record overflow"
	alertDescriptionMap[Alert_HandShake_Failure] = "Handshake failure"
	alertDescriptionMap[Alert_Bad_Certificate] = "Bad certificate"
	alertDescriptionMap[Alert_Unsupported_Certificate] = "Unsupported certificate"
	alertDescriptionMap[Alert_Certificate_Revoked] = "Certificate revoked"
	alertDescriptionMap[Alert_Certificate_Expired] = "Certificate expired"
	alertDescriptionMap[Alert_Certificate_Unknown] = "Certificate unknown"
	alertDescriptionMap[Alert_Illegal_Parameters] = "Illegal parameters"
	alertDescriptionMap[Alert_Unknown_Call] = "Unknown call"
	alertDescriptionMap[Alert_Access_Denied] = "Access denied"
	alertDescriptionMap[Alert_Decode_Error] = "Decode error"
	alertDescriptionMap[Alert_Decrypt_Error] = "Decrypt error"
	alertDescriptionMap[Alert_Protocol_Version] = "Protocol Version"
	alertDescriptionMap[Alert_Insufficient_Security] = "Insufficient Security"
	alertDescriptionMap[Alert_Internal_Error] = "Internal Error"
	alertDescriptionMap[Alert_Inappropriate_Fallback] = "Inappropriate fallback"
	alertDescriptionMap[Alert_User_Canceled] = "User Canceled"
	alertDescriptionMap[Alert_Missing_Extension] = "Missing extension"
	alertDescriptionMap[Alert_Unsupported_Extension] = "Unsupported extension"
	alertDescriptionMap[Alert_Unrecognized_Name] = "Unrecognized name"
	alertDescriptionMap[Alert_Bad_Certificate_Status_Response] = "Bad certificate status response"
	alertDescriptionMap[Alert_Unknow_PSK_Identity] = "Unknow PSK Identity"
	alertDescriptionMap[Alert_Ceritificate_Required] = "Certificate required"
	alertDescriptionMap[Alert_No_Application_Protocol] = "No application protocol"
}

type Alert struct {
	AlertLevel       AlertLevel
	AlertDescription AlertDescription
}

func NewAlert(level AlertLevel, description AlertDescription) *Alert {
	return &Alert{
		AlertLevel:       level,
		AlertDescription: description,
	}
}

func (a *Alert) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, a.AlertLevel)
	_ = binary.Write(buf, binary.BigEndian, a.AlertDescription)
	return buf.Bytes()
}

func (a *Alert) Deserialize(data []byte) int {
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.BigEndian, &a.AlertLevel)
	_ = binary.Read(buf, binary.BigEndian, &a.AlertDescription)
	return len(data) - buf.Len()
}

func (a *Alert) String() string {
	return fmt.Sprintf("Alert{level: %s (%d) - description: %s (%d)}", alertLevelMap[a.AlertLevel], a.AlertLevel, alertDescriptionMap[a.AlertDescription], a.AlertDescription)
}
