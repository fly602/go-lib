/*
 * Copyright (C) 2015 ~ 2022 Deepin Technology Co., Ltd.
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
package sm2

// #cgo pkg-config: libssl libcrypto
// #include "dde-sm2.h"
// #include <stdlib.h>
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// SM2Helper provides SM2 encryption/decryption functionality
type SM2Helper struct {
	context *C.sm2_context
}

// NewHelper creates a new SM2Helper instance
func NewHelper() *SM2Helper {
	context := C.new_sm2_context()
	if context == nil {
		return nil
	}
	helper := &SM2Helper{
		context: context,
	}
	// Set finalizer to ensure cleanup if Release() is not called
	runtime.SetFinalizer(helper, (*SM2Helper).finalize)
	return helper
}

// finalize is called by garbage collector if Release() wasn't called
func (s *SM2Helper) finalize() {
	if s.context != nil {
		C.free_sm2_context(s.context)
		s.context = nil
	}
}

// GenPairKey generates and returns public and private key pair
func (s *SM2Helper) GenPairKey() (string, string, error) {
	if s.context == nil {
		return "", "", errors.New("SM2Helper context is nil")
	}

	pub := C.get_sm2_public_key(s.context)
	pri := C.get_sm2_private_key(s.context)

	if pub == nil || pri == nil {
		return "", "", errors.New("failed to generate key pair")
	}

	return C.GoString(pub), C.GoString(pri), nil
}

// Encrypt encrypts plaintext using SM2 algorithm
func (s *SM2Helper) Encrypt(plaintext []byte) ([]byte, error) {
	if s.context == nil {
		return nil, errors.New("SM2Helper context is nil")
	}

	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	inPtr := (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	inLen := C.size_t(len(plaintext))

	var outPtr *C.uchar
	var outLen C.size_t

	res := C.sm2_encrypt(s.context, inPtr, inLen, &outPtr, &outLen)
	if res != 0 {
		return nil, fmt.Errorf("sm2 encrypt failed with code %d", res)
	}

	if outPtr == nil || outLen <= 0 {
		return nil, errors.New("encryption returned null or empty result")
	}

	// Convert C result back to Go slice
	ciphertext := C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))

	// Free the C allocated memory
	C.free(unsafe.Pointer(outPtr))

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using SM2 algorithm
func (s *SM2Helper) Decrypt(ciphertext []byte) ([]byte, error) {
	if s.context == nil {
		return nil, errors.New("SM2Helper context is nil")
	}

	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}

	inPtr := (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
	inLen := C.size_t(len(ciphertext))

	var outPtr *C.uchar
	var outLen C.size_t

	res := C.sm2_decrypt(s.context, inPtr, inLen, &outPtr, &outLen)
	if res != 0 {
		return nil, fmt.Errorf("sm2 decrypt failed with code %d", res)
	}

	if outPtr == nil || outLen <= 0 {
		return nil, errors.New("decryption returned null or empty result")
	}

	// Convert C result back to Go slice
	plaintext := C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))

	// Free the C allocated memory
	C.free(unsafe.Pointer(outPtr))

	return plaintext, nil
}

// Release frees the SM2Helper resources
// It's safe to call multiple times
func (s *SM2Helper) Release() {
	if s.context != nil {
		runtime.SetFinalizer(s, nil) // Remove finalizer since we're cleaning up manually
		C.free_sm2_context(s.context)
		s.context = nil
	}
}
