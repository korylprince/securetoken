package securetoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	keySize      = 32 //AES-256
	tsOffset     = 0
	tsSize       = 8 //uint64
	nonceOffset  = tsOffset + tsSize
	nonceSize    = 12 //NIST recommended nonce size
	cipherOffset = nonceOffset + nonceSize
	tagSize      = 16
	minTokenSize = tsSize + nonceSize + tagSize
)

//NewKey returns a newly generated key, or an error if one occurred
func NewKey() ([]byte, error) {
	//generate key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("Unable to create key: %v", err)
	}

	//base64url encode key
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(key)))
	base64.URLEncoding.Encode(encoded, key)
	return encoded, nil
}

//NewAEAD returns a new AES-GCM with the given key, or an error if one occurrred
func NewAEAD(key []byte) (cipher.AEAD, error) {
	//base64url decoded key
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(key)))
	n, err := base64.URLEncoding.Decode(decoded, key)
	if err != nil {
		return nil, fmt.Errorf("Unable to base64url decode key: %v", err)
	}
	decoded = decoded[:n]

	//check key length
	if len(decoded) != keySize {
		return nil, fmt.Errorf("Invalid key size: %d", len(decoded))
	}

	block, err := aes.NewCipher(decoded)
	if err != nil {
		return nil, fmt.Errorf("Unable to create AES block: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Unable to create AES-GCM: %v", err)
	}
	return aead, nil
}

//NewToken returns a new token created from the given plaintext and key, or an error if one occurred
func NewToken(plaintext, key []byte) ([]byte, error) {
	//record time
	ts := make([]byte, tsSize)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().UnixNano()))

	//decode key and create GCM
	aead, err := NewAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to create AEAD: %v", err)
	}

	//generate nonce
	nonce := make([]byte, nonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("Unable to create nonce: %v", err)
	}

	//encrypt plaintext
	ciphertext := aead.Seal(nil, nonce, plaintext, ts)

	//concatenate token
	token := append(ts, nonce...)
	token = append(token, ciphertext...)

	//base64url encode token
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(token)))
	base64.URLEncoding.Encode(encoded, token)
	return encoded, nil
}

//DecryptToken returns the plaintext for the given token and key, or an error if one occurred.
//If ttl is non-zero then the token's timestamp is checked to make sure it was created within ttl ago
func DecryptToken(token, key []byte, ttl time.Duration) ([]byte, error) {
	//decode key and create GCM
	aead, err := NewAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to create AEAD: %v", err)
	}

	//base64url decode the token
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(token)))
	n, err := base64.URLEncoding.Decode(decoded, token)
	if err != nil {
		return nil, fmt.Errorf("Unable to base64url decode token: %v", err)
	}
	decoded = decoded[:n]

	//check token length
	if len(decoded) < minTokenSize {
		return nil, errors.New("Unable to decode token: malformed length")
	}

	//separate token
	tsBytes := decoded[tsOffset : tsOffset+tsSize]
	nonce := decoded[nonceOffset : nonceOffset+nonceSize]
	ciphertext := decoded[cipherOffset:]

	//verify and decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, tsBytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to authenticate token: %v", err)
	}

	//check timestamp
	if ttl != 0 && uint64(time.Now().UnixNano())-binary.BigEndian.Uint64(tsBytes) > uint64(ttl.Nanoseconds()) {
		return nil, errors.New("Unable to authenticate token: token expired")
	}

	return plaintext, nil
}
