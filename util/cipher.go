package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"strings"
)

func AesEncrypt(key []byte, text []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic("AesEncrypt:NewCipher: " + err.Error())
	}

	msg := Pad(text)
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic("AesEncrypt:ReadFull: " + err.Error())
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], msg)
	finalMsg := removeBase64Padding(base64.URLEncoding.EncodeToString(ciphertext))

	return []byte(finalMsg), nil
}

func AesDecrypt(key []byte, text []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic("NewCipher: " + err.Error())
	}
	decodedMsg, err := base64.URLEncoding.DecodeString(addBase64Padding(string(text)))
	if err != nil {
		return nil, errors.New("AesEncrypt:DecodeString: " + err.Error())
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return nil, errors.New("AesEncrypt:BlockSize Diff: " + err.Error())
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	unpadMsg, err := Unpad(msg)
	if err != nil {
		return nil, errors.New("AesEncrypt:Unpad: " + err.Error())
	}
	return unpadMsg, nil
}

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		log.Fatal("Unpad:unpadding > length: ",unpadding,length)
	}
	return src[:(length - unpadding)], nil
}

func addBase64Padding(value string) string {
	m := len(value) % 4
	if m != 0 {
		value += strings.Repeat("=", 4-m)
	}
	return value
}

func removeBase64Padding(value string) string {
	return strings.Replace(value, "=", "", -1)
}
