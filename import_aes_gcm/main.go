package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const ()

func main() {

	secret := "change this password to a secret"
	rawKey := []byte(secret)

	tk, err := subtle.NewAESGCM(rawKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	k := &gcmpb.AesGcmKey{
		Version:  0,
		KeyValue: tk.Key,
	}

	serialized, err := proto.Marshal(k)
	if err != nil {
		log.Fatal(err)
	}

	id := rand.Uint32()
	ks := &tinkpb.Keyset{
		PrimaryKeyId: id,
		Key: []*tinkpb.Keyset_Key{{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmKey",
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value:           serialized,
			},
			KeyId:            id,
			Status:           tinkpb.KeyStatusType_ENABLED,
			OutputPrefixType: tinkpb.OutputPrefixType_TINK,
		},
		},
	}

	nkh, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		log.Fatal(err)
	}

	ksw := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(nkh, ksw); err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.Write(ksw.Keyset); err != nil {
		log.Fatalf("Could not write encrypted keyhandle %v", err)

	}

	bbw := new(bytes.Buffer)
	bw := keyset.NewBinaryWriter(bbw)
	if err := bw.Write(ksw.Keyset); err != nil {
		log.Fatalf("Could not write encrypted keyhandle %v", err)

	}

	log.Println("Tink Keyset Encoded: ", base64.StdEncoding.EncodeToString(bbw.Bytes()))

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}

	log.Println("Tink Keyset:\n", prettyJSON.String())

	a, err := aead.New(nkh)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Attempt to decrypt with BQ output\n")

	bqCiphers := []string{"AZrLBEKaUq6kFMfPY7XzKcFxvSCJQ31WYqnJEPAzsHPhk6WQ0S4=", "AZrLBEL2mv3fZ05icMISrDXdN35gtAX54Z4zqDN0rDevfsfSFoY=", "AZrLBEKjpZf+H+JIFijHakbiHtrtY09GNPTrpeHL95CYZj+jk/8="}

	for _, bc := range bqCiphers {
		bb, err := base64.StdEncoding.DecodeString(bc)
		if err != nil {
			log.Fatal(err)
		}

		dl, err := a.Decrypt(bb, []byte(""))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Plain text Decrypted from BQ: %s\n", string(dl))
	}

	// 14. Extract and print raw Encryption Key from keySet
	for _, kk := range ks.Key {
		kserialized := kk.KeyData.Value
		rk := &gcmpb.AesGcmKey{}

		err := proto.Unmarshal(kserialized, rk)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("ReCreated Raw Key: %s", string(rk.KeyValue))
	}

	// 15. Optionally write the keyset to a file

	buf = new(bytes.Buffer)
	w = keyset.NewJSONWriter(buf)
	if err := w.Write(ks); err != nil {
		log.Fatalf("cannot write encrypted keyset: %v", err)
	}
	err = ioutil.WriteFile("keyset.json", buf.Bytes(), 0644)
	if err != nil {
		log.Fatal("cannot write encrypted keyset: %v", err)
	}

}
