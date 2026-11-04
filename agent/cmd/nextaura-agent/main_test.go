package main

import (
	"strings"
	"testing"
)

func TestReadEnrollmentCodeFromStdin(t *testing.T) {
	got, err := readEnrollmentCode(strings.NewReader("  ABCDE-FGHIJ-KLMNO  \n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "ABCDE-FGHIJ-KLMNO" {
		t.Fatalf("unexpected code %q", got)
	}
}

func TestReadEnrollmentCodeRejectsEmptyAndOversizedInput(t *testing.T) {
	for name, input := range map[string]string{
		"empty":     " \n",
		"oversized": strings.Repeat("A", 257),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readEnrollmentCode(strings.NewReader(input)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
