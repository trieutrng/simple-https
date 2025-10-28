package config

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

type Log4jFormatter struct{}

func (f *Log4jFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b bytes.Buffer

	// Timestamp in Log4j format: yyyy-MM-dd HH:mm:ss,SSS
	timestamp := entry.Time.Format("2006-01-02 15:04:05.000")

	// Level (align to width 5 like Log4j)
	level := fmt.Sprintf("%-5s", entry.Level.String())

	// Logger name (you can store it in the entry.Data map)
	loggerName, ok := entry.Data["logger"]
	if !ok {
		loggerName = "."
	}

	// Write line: timestamp LEVEL [logger] - message
	b.WriteString(fmt.Sprintf("%s %s [%s] - %s\n", timestamp, strings.ToUpper(level), loggerName, entry.Message))
	return b.Bytes(), nil
}
