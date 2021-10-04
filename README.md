# Importing and extracting external keys for BigQuery AEAD Tink KeySets


[BigQuery AEAD encryption](https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts) functions uses [TINK Keysets](https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets).  

Works fine but all samples included there describe how to generate an encoded key using a BQ function itself: [KEYS.NEW_KEYSET('AEAD_AES_GCM_256')](https://cloud.google.com/bigquery/docs/reference/standard-sql/aead_encryption_functions#keysnew_keyset)

However, what if you 

`a)` already have a _raw_ `AEAD_AES_GCM_256` that you want to use with BQ
  or
`b)` you've already generated a Key within BQ and want to extract the base `AEAD_AES_GCM_256` from a keyset and want to decrypt it on a sunday like as i'm writing this today.

you're probably wondering how to do that?

well

- for `a)` you need to create a Tink Keyset from a raw AES key

- for `b)` you need to extract an AES key from an existing TINK keyset

thats what you can use this repo for..

---

### Importing to Tink

If the AES_GCM key is:

```golang
	// 1. AES GCM Key
	secret := "change this password to a secret"
```

then import that into a tink keyset.  You can use the encoded key with Bigquery

```log
$ go run import_aes_gcm/main.go 

Tink Keyset Encoded:  CMKIrNYJEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIGNoYW5nZSB0aGlzIHBhc3N3b3JkIHRvIGEgc2VjcmV0GAEQARjCiKzWCSAB
Tink Keyset:
 {
	"primaryKeyId": 2596996162,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
				"value": "GiBjaGFuZ2UgdGhpcyBwYXNzd29yZCB0byBhIHNlY3JldA==",
				"keyMaterialType": "SYMMETRIC"
			},
			"status": "ENABLED",
			"keyId": 2596996162,
			"outputPrefixType": "TINK"
		}
	]
}

Attempt to decrypt with BQ output
Plain text Decrypted from BQ: Greed
Plain text Decrypted from BQ: Greed
Plain text Decrypted from BQ: Greed
ReCreated Raw Key: change this password to a secret
```

use the encoded key with the key of your choosing with [AEAD.ENCRYPT](https://cloud.google.com/bigquery/docs/reference/standard-sql/aead_encryption_functions#aeadencrypt) function

```sql
$ bq query --nouse_legacy_sql --parameter=keyset1::CMKIrNYJEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIGNoYW5nZSB0aGlzIHBhc3N3b3JkIHRvIGEgc2VjcmV0GAEQARjCiKzWCSAB \ '
SELECT
  title,AEAD.ENCRYPT(FROM_BASE64(@keyset1),title,"")
FROM
  bigquery-public-data.san_francisco_film_locations.film_locations
WHERE
  title = "Greed"
'

+-------+------------------------------------------------------+
| title |                         f0_                          |
+-------+------------------------------------------------------+
| Greed | AZrLBEKaUq6kFMfPY7XzKcFxvSCJQ31WYqnJEPAzsHPhk6WQ0S4= |
| Greed | AZrLBEL2mv3fZ05icMISrDXdN35gtAX54Z4zqDN0rDevfsfSFoY= |
| Greed | AZrLBEKjpZf+H+JIFijHakbiHtrtY09GNPTrpeHL95CYZj+jk/8= |
+-------+------------------------------------------------------+
```

then decrypt the BQ output using [AEAD.DECRYPT](https://cloud.google.com/bigquery/docs/reference/standard-sql/aead_encryption_functions#aeaddecrypt_string) and the key you generated

```sql
bq query --nouse_legacy_sql --parameter=keyset1::CMKIrNYJEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIGNoYW5nZSB0aGlzIHBhc3N3b3JkIHRvIGEgc2VjcmV0GAEQARjCiKzWCSAB \ '
SELECT
  AEAD.DECRYPT_STRING(FROM_BASE64(@keyset1),FROM_BASE64("AZrLBEKaUq6kFMfPY7XzKcFxvSCJQ31WYqnJEPAzsHPhk6WQ0S4="),""),
  AEAD.DECRYPT_STRING(FROM_BASE64(@keyset1),FROM_BASE64("AZrLBEL2mv3fZ05icMISrDXdN35gtAX54Z4zqDN0rDevfsfSFoY="),""),
  AEAD.DECRYPT_STRING(FROM_BASE64(@keyset1),FROM_BASE64("AZrLBEKjpZf+H+JIFijHakbiHtrtY09GNPTrpeHL95CYZj+jk/8="),""),    
'

+-------+-------+-------+
|  f0_  |  f1_  |  f2_  |
+-------+-------+-------+
| Greed | Greed | Greed |
+-------+-------+-------+
```

Just as verification you can even use golang to verify too using the keyset you just imported the raw key into

```golang

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
```

## Exporting from TINK

To do the reverse (extract a key from tink, see the sample in this repo here which will unmarshall the encoded key.  Your key here for BQ is 

```golang
const (
	keySetString = "CMKIrNYJEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIGNoYW5nZSB0aGlzIHBhc3N3b3JkIHRvIGEgc2VjcmV0GAEQARjCiKzWCSAB"
)
```


which is actually the same raw key from above: `change this password to a secret`

```log
$ go run export_aes_gcm/main.go 
Tink Keyset:
 {
	"primaryKeyId": 2596996162,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
				"value": "GiBjaGFuZ2UgdGhpcyBwYXNzd29yZCB0byBhIHNlY3JldA==",
				"keyMaterialType": "SYMMETRIC"
			},
			"status": "ENABLED",
			"keyId": 2596996162,
			"outputPrefixType": "TINK"
		}
	]
}

Encrypted Data: AZrLBELglGoDvAXMqIT+N7J8Pu6VPBHwM2Hp5Z6tS0Z1Py9szPk=
Plain text: Greed
Extracted Raw Key: change this password to a secret
```

---

references


for more refernces, see [https://github.com/salrashid123/tink_samples](https://github.com/salrashid123/tink_samples)


You can also use [tinkkey](https://developers.google.com/tink/install-tinkey) to manage a keyset

```bash
$ ./tinkey list-keyset --in-format=json --in keyset.json
primary_key_id: 2596996162
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
  status: ENABLED
  key_id: 2596996162
  output_prefix_type: TINK
}

$ ./tinkey rotate-keyset --in-format=json --in keyset.json  --key-template AES256_GCM --out-format=json --out keyset2.json

$ ./tinkey list-keyset --in-format=json --in keyset2.json
primary_key_id: 2130552249
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
  status: ENABLED
  key_id: 2596996162
  output_prefix_type: TINK
}
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
  status: ENABLED
  key_id: 2130552249
  output_prefix_type: TINK
}
```
