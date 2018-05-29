package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type input struct {
	Key, EncryptedMessage, Nonce string
}

func initDecrypt(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	var fromReq input
	err = json.Unmarshal(body, &fromReq)
	if err != nil {
		panic(err)
	}
	if fromReq.Key == "" {
		fmt.Print(w, "Request received without key.")
		fmt.Fprint(w, "A key is required for decryption.")
		panic("A key is required for decryption.")
	}
	if fromReq.EncryptedMessage == "" {
		fmt.Print(w, "Request received without encrypted message.")
		fmt.Fprint(w, "A valid encrypted message is required for decryption.")
		panic("A valid encrypted message is required for decryption.")
	}
	if fromReq.Nonce == "" {
		fmt.Print(w, "Request received without nonce.")
		fmt.Fprint(w, "A valid nonce is required for decryption.")
		panic("A valid nonce is required for decryption.")
	}
	message := decrypt(fromReq.Key, fromReq.EncryptedMessage, fromReq.Nonce)
	fmt.Printf("{\"Message\":\"%s\"}", message)
	fmt.Fprintf(w, "{\"Message\":\"%s\"}", message)
}

func main() {
	http.HandleFunc("/", initDecrypt)
	fmt.Println("listening on port 3000...")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatal(err)
	}
}

func decrypt(reqKey, reqMessage, nonce string) []byte {
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString(reqKey)
	ciphertext, _ := hex.DecodeString(reqMessage)
	reqNonce, _ := hex.DecodeString(nonce)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err := aesgcm.Open(nil, reqNonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	//fmt.Printf("%s\n", plaintext)
	return plaintext
}
