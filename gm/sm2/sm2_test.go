package sm2

import (
	"reflect"
	"testing"
)

func Test_encryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		plainText string
	}{
		{"simple", "12345"},
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
		{"unicode", "测试中文加密解密功能"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper := NewHelper()
			if helper == nil {
				t.Fatalf("new sm2 helper failed")
			}
			defer helper.Release()

			// Test key generation
			pubKey, privKey, err := helper.GenPairKey()
			if err != nil {
				t.Fatalf("generate key pair failed: %v", err)
			}
			if pubKey == "" || privKey == "" {
				t.Fatalf("generated keys are empty")
			}

			// Skip empty plaintext test as it should return error
			if tt.plainText == "" {
				_, err := helper.Encrypt([]byte(tt.plainText))
				if err == nil {
					t.Errorf("Expected error for empty plaintext, got nil")
				}
				return
			}

			ciphertext, err := helper.Encrypt([]byte(tt.plainText))
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			if len(ciphertext) == 0 {
				t.Fatalf("ciphertext is empty")
			}

			plaintext, err := helper.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func Test_errorHandling(t *testing.T) {
	t.Run("nil context operations", func(t *testing.T) {
		helper := &SM2Helper{context: nil}

		_, _, err := helper.GenPairKey()
		if err == nil {
			t.Error("Expected error for GenPairKey with nil context")
		}

		_, err = helper.Encrypt([]byte("test"))
		if err == nil {
			t.Error("Expected error for Encrypt with nil context")
		}

		_, err = helper.Decrypt([]byte("test"))
		if err == nil {
			t.Error("Expected error for Decrypt with nil context")
		}

		// Should not panic
		helper.Release()
	})

	t.Run("empty data handling", func(t *testing.T) {
		helper := NewHelper()
		if helper == nil {
			t.Fatalf("new sm2 helper failed")
		}
		defer helper.Release()

		_, err := helper.Encrypt([]byte{})
		if err == nil {
			t.Error("Expected error for empty plaintext")
		}

		_, err = helper.Decrypt([]byte{})
		if err == nil {
			t.Error("Expected error for empty ciphertext")
		}
	})
}
