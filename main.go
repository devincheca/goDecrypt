package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

type input struct {
	Key, Message string
}

func initEncrypt(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	var fromReq input
	err = json.Unmarshal(body, &fromReq)
	if err != nil {
		panic(err)
	}
	eMessage, nonce := encrypt(fromReq.Key, fromReq.Message)
	encryptMessage := fmt.Sprintf("%x", eMessage)
	nonceString := fmt.Sprintf("%x", nonce)
	fmt.Print("{\"EncryptedMessage\":\"", encryptMessage, "\",")
	fmt.Print("\"Nonce\":\"", nonceString, "\"}")
	fmt.Fprint(w, "{\"EncryptedMessage\":\"", encryptMessage, "\",")
	fmt.Fprint(w, "\"Nonce\":\"", nonceString, "\"}")
}

func main() {
	http.HandleFunc("/", initEncrypt)
	fmt.Println("listening on port 3000...")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatal(err)
	}
}

func encrypt(reqKey, reqMessage string) ([]byte, []byte) {
	// When decoded the key should be 16 bytes (AES-128)// or 32 (AES-256).
	key, _ := hex.DecodeString(reqKey)//"6368616e676520746869732070617373776f726420746f206120736563726574")
	//679098d868ee8129c72a23ec323d3febb513286c3cdf3c837adfe39721f50032
	plaintext := []byte(reqMessage)

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Key needs to be 16 bytes (AES-128) compliant")
		panic(err.Error())
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
//	nonce, _ := hex.DecodeString("afb8a7579bf971db9f8ceeed")//nonce, _ := hex.DecodeString("TestNonce123456789876543")
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	//fmt.Printf("%x\n", ciphertext)
	return ciphertext, nonce
}

func decrypt(reqKey string, reqMessage, nonce []byte) []byte {
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString(reqKey)//"6368616e676520746869732070617373776f726420746f206120736563726574")
	ciphertext := reqMessage//, _ := hex.DecodeString(reqMessage)//"c3aaa29f002ca75870806e44086700f62ce4d43e902b3888e23ceff797a7a471")
	//nonce, _ := hex.DecodeString("afb8a7579bf971db9f8ceeed")//nonce, _ := hex.DecodeString("TestNonce123456789876543")//nonce := make([]byte, 12)//, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%s\n", plaintext)
	return plaintext
}
