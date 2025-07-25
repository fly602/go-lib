/*
 * Copyright (C) 2015 ~ 2025 Deepin Technology Co., Ltd.
 *
 * Author:     liaohanqin <liaohanqin@uniontech.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package sm4

/*
#cgo LDFLAGS: -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define EVP_TYPE_ENC 1
#define EVP_TYPE_DEC 0

// 简化的日志函数 (避免依赖common/log.h)
static void simple_log(const char* msg) {
    // 静默处理或可以输出到stderr
    // fprintf(stderr, "SM4 Warning: %s\n", msg);
}

// 生成16字节对称密钥的函数
unsigned char *generate_sm4_key() {
    unsigned char *key = (unsigned char *)malloc(16);
    if (!key) return NULL;

    // 使用OpenSSL的随机数生成器
    if (RAND_bytes(key, 16) != 1) {
        free(key);
        return NULL;
    }
    return key;
}

// EVP处理函数的简化实现
int evp_deal(const EVP_CIPHER *cip, int padding, int enc, const unsigned char *key, const unsigned char *iv, const unsigned char *in, int inLen, unsigned char **out, int *outLen) {
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = -1;

    if (cip == NULL || key == NULL || in == NULL || out == NULL || outLen == NULL || inLen <= 0) {
        simple_log("invalid params");
        goto end;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        simple_log("failed to create EVP context");
        goto end;
    }

    int initRet = EVP_CipherInit(ctx, cip, key, iv, enc);
    if (1 != initRet) {
        simple_log("failed to init cipher");
        goto end;
    }

    if (padding > 0) {
        if (!EVP_CIPHER_CTX_set_padding(ctx, padding)) {
            simple_log("failed to set padding");
            goto end;
        }
    }

    unsigned char *outBuf = (unsigned char *)calloc(inLen + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));
    if (!outBuf) {
        simple_log("failed to allocate output buffer");
        goto end;
    }

    int outBufLen, tmpLen;
    if (!EVP_CipherUpdate(ctx, outBuf, &outBufLen, in, inLen)) {
        simple_log("failed to update cipher");
        free(outBuf);
        goto end;
    }

    if (!EVP_CipherFinal_ex(ctx, outBuf + outBufLen, &tmpLen)) {
        simple_log("failed to finalize cipher");
        free(outBuf);
        goto end;
    }

    outBufLen += tmpLen;
    *out = outBuf;
    *outLen = outBufLen;
    ret = 0;

end:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}

// Wrapper functions for SM4 operations
int sm4_ecb_encrypt_wrapper(const unsigned char *key, const unsigned char *in, int inLen, unsigned char **out, int *outLen) {
    return evp_deal(EVP_sm4_ecb(), -1, EVP_TYPE_ENC, key, NULL, in, inLen, out, outLen);
}

int sm4_ecb_decrypt_wrapper(const unsigned char *key, const unsigned char *in, int inLen, unsigned char **out, int *outLen) {
    return evp_deal(EVP_sm4_ecb(), -1, EVP_TYPE_DEC, key, NULL, in, inLen, out, outLen);
}

int sm4_cbc_encrypt_wrapper(const unsigned char *key, const unsigned char *iv, const unsigned char *in, int inLen, unsigned char **out, int *outLen) {
    return evp_deal(EVP_sm4_cbc(), -1, EVP_TYPE_ENC, key, iv, in, inLen, out, outLen);
}

int sm4_cbc_decrypt_wrapper(const unsigned char *key, const unsigned char *iv, const unsigned char *in, int inLen, unsigned char **out, int *outLen) {
    return evp_deal(EVP_sm4_cbc(), -1, EVP_TYPE_DEC, key, iv, in, inLen, out, outLen);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const (
	// SM4 block size is 16 bytes
	BlockSize = 16
	// SM4 key size is 16 bytes
	KeySize = 16
)

// SM4 error definitions
var (
	ErrInvalidKeySize = errors.New("invalid key size, must be 16 bytes")
	ErrInvalidIVSize  = errors.New("invalid IV size, must be 16 bytes")
)

const (
	ModeECB = iota
	ModeCBC
)

type sm4Cipher struct {
	key  []byte
	iv   []byte
	mode int
}

// ECBEncrypt encrypts data using SM4 ECB mode
func ECBEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	// Convert Go slices to C pointers
	keyPtr := (*C.uchar)(unsafe.Pointer(&key[0]))
	inPtr := (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	inLen := C.int(len(plaintext))

	var outPtr *C.uchar
	var outLen C.int

	// Call C function
	result := C.sm4_ecb_encrypt_wrapper(keyPtr, inPtr, inLen, &outPtr, &outLen)
	if result != 0 {
		return nil, fmt.Errorf("SM4 ECB encryption failed with code: %d", result)
	}

	if outPtr == nil || outLen <= 0 {
		return nil, errors.New("encryption returned null or empty result")
	}

	// Convert C result back to Go slice
	ciphertext := C.GoBytes(unsafe.Pointer(outPtr), outLen)

	// Free the C allocated memory
	C.free(unsafe.Pointer(outPtr))

	return ciphertext, nil
}

// ECBDecrypt decrypts data using SM4 ECB mode
func ECBDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}

	// Convert Go slices to C pointers
	keyPtr := (*C.uchar)(unsafe.Pointer(&key[0]))
	inPtr := (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
	inLen := C.int(len(ciphertext))

	var outPtr *C.uchar
	var outLen C.int

	// Call C function
	result := C.sm4_ecb_decrypt_wrapper(keyPtr, inPtr, inLen, &outPtr, &outLen)
	if result != 0 {
		return nil, fmt.Errorf("SM4 ECB decryption failed with code: %d", result)
	}

	if outPtr == nil || outLen <= 0 {
		return nil, errors.New("decryption returned null or empty result")
	}

	// Convert C result back to Go slice
	plaintext := C.GoBytes(unsafe.Pointer(outPtr), outLen)

	// Free the C allocated memory
	C.free(unsafe.Pointer(outPtr))

	return plaintext, nil
}

// CBCEncrypt encrypts data using SM4 CBC mode
func CBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	if len(iv) != BlockSize {
		return nil, ErrInvalidIVSize
	}

	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	// Convert Go slices to C pointers
	keyPtr := (*C.uchar)(unsafe.Pointer(&key[0]))
	ivPtr := (*C.uchar)(unsafe.Pointer(&iv[0]))
	inPtr := (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	inLen := C.int(len(plaintext))

	var outPtr *C.uchar
	var outLen C.int

	// Call C function
	result := C.sm4_cbc_encrypt_wrapper(keyPtr, ivPtr, inPtr, inLen, &outPtr, &outLen)
	if result != 0 {
		return nil, fmt.Errorf("SM4 CBC encryption failed with code: %d", result)
	}

	if outPtr == nil || outLen <= 0 {
		return nil, errors.New("encryption returned null or empty result")
	}

	// Convert C result back to Go slice
	ciphertext := C.GoBytes(unsafe.Pointer(outPtr), outLen)

	// Free the C allocated memory
	C.free(unsafe.Pointer(outPtr))

	return ciphertext, nil
}

// CBCDecrypt decrypts data using SM4 CBC mode
func CBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	if len(iv) != BlockSize {
		return nil, ErrInvalidIVSize
	}

	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}

	// Convert Go slices to C pointers
	keyPtr := (*C.uchar)(unsafe.Pointer(&key[0]))
	ivPtr := (*C.uchar)(unsafe.Pointer(&iv[0]))
	inPtr := (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
	inLen := C.int(len(ciphertext))

	var outPtr *C.uchar
	var outLen C.int

	// Call C function
	result := C.sm4_cbc_decrypt_wrapper(keyPtr, ivPtr, inPtr, inLen, &outPtr, &outLen)
	if result != 0 {
		return nil, fmt.Errorf("SM4 CBC decryption failed with code: %d", result)
	}

	if outPtr == nil || outLen <= 0 {
		return nil, errors.New("decryption returned null or empty result")
	}

	// Convert C result back to Go slice
	plaintext := C.GoBytes(unsafe.Pointer(outPtr), outLen)

	// Free the C allocated memory
	C.free(unsafe.Pointer(outPtr))

	return plaintext, nil
}

// GenerateKey generates a random 16-byte key for SM4
func GenerateKey() ([]byte, error) {
	keyPtr := C.generate_sm4_key()
	if keyPtr == nil {
		return nil, errors.New("failed to generate SM4 key")
	}

	// Convert C result to Go slice (16 bytes for SM4)
	key := C.GoBytes(unsafe.Pointer(keyPtr), KeySize)

	// Free the C allocated memory
	C.free(unsafe.Pointer(keyPtr))

	return key, nil
}

// C-style wrapper functions to match the original API

// SM4ECBEncrypt encrypts data using SM4 ECB mode (C-style wrapper)
func SM4ECBEncrypt(key, in []byte) ([]byte, error) {
	return ECBEncrypt(key, in)
}

// SM4ECBDecrypt decrypts data using SM4 ECB mode (C-style wrapper)
func SM4ECBDecrypt(key, in []byte) ([]byte, error) {
	return ECBDecrypt(key, in)
}

// SM4CBCEncrypt encrypts data using SM4 CBC mode (C-style wrapper)
func SM4CBCEncrypt(key, iv, in []byte) ([]byte, error) {
	return CBCEncrypt(key, iv, in)
}

// SM4CBCDecrypt decrypts data using SM4 CBC mode (C-style wrapper)
func SM4CBCDecrypt(key, iv, in []byte) ([]byte, error) {
	return CBCDecrypt(key, iv, in)
}

func NewCipher(key, iv []byte, mode int) (*sm4Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	if mode == ModeCBC && (iv == nil || len(iv) != BlockSize) {
		return nil, ErrInvalidIVSize
	}

	if len(iv) != BlockSize {
		return nil, ErrInvalidIVSize
	}

	return &sm4Cipher{key: key, iv: iv, mode: mode}, nil
}

func (c *sm4Cipher) Encrypt(dst, src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, errors.New("src cannot be empty")
	}

	if c.mode == ModeECB {
		return ECBEncrypt(c.key, src)
	}

	return CBCEncrypt(c.key, c.iv, src)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, errors.New("src cannot be empty")
	}

	if c.mode == ModeECB {
		return ECBDecrypt(c.key, src)
	}

	return CBCDecrypt(c.key, c.iv, src)
}
