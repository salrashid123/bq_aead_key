package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

const (
	keySetString = "CMKIrNYJEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIGNoYW5nZSB0aGlzIHBhc3N3b3JkIHRvIGEgc2VjcmV0GAEQARjCiKzWCSAB"
)

func main() {

	decoded, err := base64.StdEncoding.DecodeString(keySetString)
	if err != nil {
		log.Fatal(err)
	}

	ksr := keyset.NewBinaryReader(bytes.NewBuffer(decoded))
	ks, err := ksr.Read()
	if err != nil {
		log.Fatal(err)
	}

	handle, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		log.Fatal(err)
	}

	a, err := aead.New(handle)
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.Write(ks); err != nil {
		log.Printf("Could not write encrypted keyhandle %v", err)
		return
	}
	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}
	log.Println("Tink Keyset:\n", string(prettyJSON.Bytes()))

	ec, err := a.Encrypt([]byte("Greed"), []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Encrypted Data: %s", base64.StdEncoding.EncodeToString(ec))

	// now read the whole thing back from scratch

	buf2 := bytes.NewBuffer(prettyJSON.Bytes())
	r := keyset.NewJSONReader(buf2)
	kh2, err := insecurecleartextkeyset.Read(r)
	if err != nil {
		log.Printf("Could not create TINK keyHandle %v", err)
		return
	}

	b, err := aead.New(kh2)
	if err != nil {
		log.Fatal(err)
	}

	dc, err := b.Decrypt(ec, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Plain text: %s\n", string(dc))

	// extract the key

	ps, err := handle.Primitives()
	if err != nil {
		log.Fatal(err)
	}

	for _, en := range ps.Entries {
		for _, e := range en {
			log.Printf("Extracted Raw Key: %v\n", string(e.Primitive.(*subtle.AESGCM).Key))
		}
	}
}
