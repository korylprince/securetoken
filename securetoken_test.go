package securetoken

import (
	"bytes"
	"testing"
	"time"
)

func TestGoodToken(t *testing.T) {
	plaintext := []byte("This is a test.")

	key, err := NewKey()
	if err != nil {
		t.Fatal("Unable to create key:", err)
	}

	token, err := NewToken(plaintext, key)
	if err != nil {
		t.Fatal("Unable to create token:", err)
	}

	pt, err := DecryptToken(token, key, 0)
	if err != nil {
		t.Fatal("Unable to decrypt token:", err)
	}

	if !bytes.Equal(plaintext, pt) {
		t.Errorf("plaintexts not equal; original: %v, returned: %v", plaintext, pt)
	}
}

func TestTokenTTL(t *testing.T) {
	plaintext := []byte("This is a test.")

	key, err := NewKey()
	if err != nil {
		t.Fatal("Unable to create key:", err)
	}

	token, err := NewToken(plaintext, key)
	if err != nil {
		t.Fatal("Unable to create token:", err)
	}

	_, err = DecryptToken(token, key, time.Second*1)
	if err != nil {
		t.Error("Unable to decrypt token:", err)
	}

	time.Sleep(time.Millisecond * 100)

	_, err = DecryptToken(token, key, time.Millisecond*100)
	if err.Error() != "Unable to authenticate token: token expired" {
		t.Errorf("Expected error to be \"%s\", instead got: \"%v\"", "Unable to authenticate token: token expired", err)
	}
}

var badTokens = []struct {
	Token       string
	Description string
	Error       string
}{
	{
		Token:       "abcd//",
		Description: "invalid base64url",
		Error:       "Unable to base64url decode token: illegal base64 data at input byte 4",
	},
	{
		Token:       "abcd",
		Description: "token too short",
		Error:       "Unable to decode token: malformed length",
	},
	{
		Token:       "Facsf83ltbKso2f5m_aXmj5mWv-tK2wY39zOmDYxKLlH8oN_dxpH2GbeMk0k27HiAe-A",
		Description: "manipulated token",
		Error:       "Unable to authenticate token: cipher: message authentication failed",
	},
}

func TestBadTokens(t *testing.T) {
	// key is all 0's
	key := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

	for _, b := range badTokens {
		if _, err := DecryptToken([]byte(b.Token), key, 0); err == nil {
			t.Error("Decrypting should have failed but didn't:", b.Description)
		} else if err.Error() != b.Error {
			t.Errorf("Mismatched Error: expected: \"%s\", result: \"%s\"", b.Error, err.Error())
		}
	}
}

var badKeys = []struct {
	Key         string
	Description string
	Error       string
}{
	{
		Key:         "abcd//",
		Description: "invalid base64url",
		Error:       "Unable to create AEAD: Unable to base64url decode key: illegal base64 data at input byte 4",
	},
	{
		Key:         "abcd",
		Description: "key too short",
		Error:       "Unable to create AEAD: Invalid key size: 3",
	},
	{
		Key:         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Description: "key too long",
		Error:       "Unable to create AEAD: Invalid key size: 33",
	},
}

func TestBadKeys(t *testing.T) {
	for _, b := range badKeys {
		if _, err := DecryptToken([]byte(""), []byte(b.Key), 0); err == nil {
			t.Error("Decrypting should have failed but didn't:", b.Description)
		} else if err.Error() != b.Error {
			t.Errorf("Mismatched Error: expected: \"%s\", result: \"%s\"", b.Error, err.Error())
		}
	}
}
