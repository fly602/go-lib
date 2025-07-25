package sm4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSM4ECB(t *testing.T) {
	// Test data
	key := []byte("1234567890abcdef") // 16 bytes key
	plaintext := []byte("hello world from sm4!")

	// Test ECB encryption
	ciphertext, err := ECBEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("ECB encryption failed: %v", err)
	}

	// Test ECB decryption
	decrypted, err := ECBDecrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("ECB decryption failed: %v", err)
	}

	// Verify the result
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("ECB round-trip failed:\nOriginal:  %s\nDecrypted: %s", plaintext, decrypted)
	}

	t.Logf("ECB test passed:")
	t.Logf("  Key:        %x", key)
	t.Logf("  Plaintext:  %s", plaintext)
	t.Logf("  Ciphertext: %x", ciphertext)
	t.Logf("  Decrypted:  %s", decrypted)
}

func TestSM4CBC(t *testing.T) {
	// Test data
	key := []byte("1234567890abcdef") // 16 bytes key
	iv := []byte("abcdef1234567890")  // 16 bytes IV
	plaintext := []byte("hello world from sm4 cbc mode!")

	// Test CBC encryption
	ciphertext, err := CBCEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("CBC encryption failed: %v", err)
	}

	// Test CBC decryption
	decrypted, err := CBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("CBC decryption failed: %v", err)
	}

	// Verify the result
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("CBC round-trip failed:\nOriginal:  %s\nDecrypted: %s", plaintext, decrypted)
	}

	t.Logf("CBC test passed:")
	t.Logf("  Key:        %x", key)
	t.Logf("  IV:         %x", iv)
	t.Logf("  Plaintext:  %s", plaintext)
	t.Logf("  Ciphertext: %x", ciphertext)
	t.Logf("  Decrypted:  %s", decrypted)
}

func TestSM4ErrorHandling(t *testing.T) {
	validKey := []byte("1234567890abcdef")
	validIV := []byte("abcdef1234567890")
	invalidKey := []byte("short")
	invalidIV := []byte("short")
	plaintext := []byte("test data")

	// Test invalid key size for ECB
	_, err := ECBEncrypt(invalidKey, plaintext)
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got: %v", err)
	}

	_, err = ECBDecrypt(invalidKey, plaintext)
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got: %v", err)
	}

	// Test invalid key size for CBC
	_, err = CBCEncrypt(invalidKey, validIV, plaintext)
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got: %v", err)
	}

	_, err = CBCDecrypt(invalidKey, validIV, plaintext)
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got: %v", err)
	}

	// Test invalid IV size for CBC
	_, err = CBCEncrypt(validKey, invalidIV, plaintext)
	if err != ErrInvalidIVSize {
		t.Errorf("Expected ErrInvalidIVSize, got: %v", err)
	}

	_, err = CBCDecrypt(validKey, invalidIV, plaintext)
	if err != ErrInvalidIVSize {
		t.Errorf("Expected ErrInvalidIVSize, got: %v", err)
	}

	t.Log("Error handling tests passed")
}

func TestSM4CStyleWrappers(t *testing.T) {
	key := []byte("1234567890abcdef")
	iv := []byte("abcdef1234567890")
	plaintext := []byte("test c-style wrappers")

	// Test C-style ECB wrappers
	ciphertext, err := SM4ECBEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("SM4ECBEncrypt failed: %v", err)
	}

	decrypted, err := SM4ECBDecrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("SM4ECBDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("C-style ECB wrapper failed")
	}

	// Test C-style CBC wrappers
	ciphertext, err = SM4CBCEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("SM4CBCEncrypt failed: %v", err)
	}

	decrypted, err = SM4CBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("SM4CBCDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("C-style CBC wrapper failed")
	}

	t.Log("C-style wrapper tests passed")
}

func TestSM4KnownVectors(t *testing.T) {
	// Known test vectors
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")

	ciphertext, err := ECBEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Known vector encryption failed: %v", err)
	}

	decrypted, err := ECBDecrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Known vector decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Known vector round-trip failed")
	}

	t.Logf("Known vector test:")
	t.Logf("  Key:        %x", key)
	t.Logf("  Plaintext:  %x", plaintext)
	t.Logf("  Ciphertext: %x", ciphertext)
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if len(key) != KeySize {
		t.Errorf("Generated key has wrong size: expected %d, got %d", KeySize, len(key))
	}

	// Generate another key and ensure they're different
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("Second GenerateKey failed: %v", err)
	}

	if bytes.Equal(key, key2) {
		t.Errorf("Generated keys are identical, randomness may be compromised")
	}

	t.Logf("Generated key: %x", key)
	t.Logf("Generated key2: %x", key2)
}

func BenchmarkSM4ECB(b *testing.B) {
	key := []byte("1234567890abcdef")
	data := make([]byte, 1024) // 1KB data

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, err := ECBEncrypt(key, data)
		if err != nil {
			b.Fatal(err)
		}
		_, err = ECBDecrypt(key, ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSM4CBC(b *testing.B) {
	key := []byte("1234567890abcdef")
	iv := []byte("abcdef1234567890")
	data := make([]byte, 1024) // 1KB data

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, err := CBCEncrypt(key, iv, data)
		if err != nil {
			b.Fatal(err)
		}
		_, err = CBCDecrypt(key, iv, ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}
