// Package logging writes plain-text logs to stderr and, optionally, a file.
// It never logs tokens or collected evidence payloads.
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

var std = log.New(os.Stderr, "", log.LstdFlags|log.LUTC)

func SetupFile(dir string) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	std.SetOutput(io.MultiWriter(os.Stderr, f))
}

func Infof(format string, a ...interface{})  { std.Output(2, "INFO  "+fmt.Sprintf(format, a...)) }
func Warnf(format string, a ...interface{})  { std.Output(2, "WARN  "+fmt.Sprintf(format, a...)) }
func Errorf(format string, a ...interface{}) { std.Output(2, "ERROR "+fmt.Sprintf(format, a...)) }
