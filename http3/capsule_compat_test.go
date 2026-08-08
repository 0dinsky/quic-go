package http3

import (
	"bytes"
	"io"
	"testing"

	"github.com/sagernet/quic-go/quicvarint"
)

func TestParseCapsuleCompatibility(t *testing.T) {
	stream := quicvarint.Append(nil, 7)
	stream = quicvarint.Append(stream, 3)
	stream = append(stream, "one"...)
	stream = quicvarint.Append(stream, 9)
	stream = quicvarint.Append(stream, 3)
	stream = append(stream, "two"...)

	reader := quicvarint.NewReader(bytes.NewReader(stream))

	firstType, firstBody, err := ParseCapsule(reader)
	if err != nil {
		t.Fatal(err)
	}
	firstValue, err := io.ReadAll(firstBody)
	if err != nil {
		t.Fatal(err)
	}
	if firstType != 7 || string(firstValue) != "one" {
		t.Fatalf("first capsule = (%d, %q), want (7, %q)", firstType, firstValue, "one")
	}

	secondType, secondBody, err := ParseCapsule(reader)
	if err != nil {
		t.Fatal(err)
	}
	secondValue, err := io.ReadAll(secondBody)
	if err != nil {
		t.Fatal(err)
	}
	if secondType != 9 || string(secondValue) != "two" {
		t.Fatalf("second capsule = (%d, %q), want (9, %q)", secondType, secondValue, "two")
	}
}
