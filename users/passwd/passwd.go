// SPDX-FileCopyrightText: 2018 - 2022 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package passwd

// #include <stdlib.h>
// #include <pwd.h>
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

var mutex sync.Mutex

// Passwd wraps up `passwd` struct used in kernel
type Passwd struct {
	Name    string
	Passwd  string // Password is encrypted
	Uid     uint32
	Gid     uint32
	Comment string
	Home    string
	Shell   string
}

// passwdC2Go converts `passwd` struct from C to golang native struct
func passwdC2Go(passwdC *C.struct_passwd) *Passwd {
	return &Passwd{
		Name:    C.GoString(passwdC.pw_name),
		Passwd:  C.GoString(passwdC.pw_passwd),
		Uid:     uint32(passwdC.pw_uid),
		Gid:     uint32(passwdC.pw_gid),
		Comment: C.GoString(passwdC.pw_gecos),
		Home:    C.GoString(passwdC.pw_dir),
		Shell:   C.GoString(passwdC.pw_shell),
	}
}

type UserNotFoundError struct {
	Name string
	Uid  uint32
}

func (err *UserNotFoundError) Error() string {
	if len(err.Name) > 0 {
		return fmt.Sprintf("User with name `%s` not found!", err.Name)
	} else {
		return fmt.Sprintf("User with uid `%d` not found!", err.Uid)
	}
}

// GetPasswdByName wraps up `getpwnam` system call.
// It retrieves records from the password file based on username.
func GetPasswdByName(name string) (*Passwd, error) {
	mutex.Lock()
	defer mutex.Unlock()
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))
	passwdC, err := C.getpwnam(nameC)
	if passwdC == nil {
		if err == nil {
			return nil, &UserNotFoundError{Name: name}
		} else {
			return nil, err
		}
	} else {
		return passwdC2Go(passwdC), nil
	}
}

// GetPasswdByUid wraps up `getpwuid` system call.
// It retrieves records from the password file based on uid.
func GetPasswdByUid(uid uint32) (*Passwd, error) {
	mutex.Lock()
	defer mutex.Unlock()
	uidC := C.__uid_t(uid)
	passwdC, err := C.getpwuid(uidC)
	if passwdC == nil {
		if err == nil {
			return nil, &UserNotFoundError{Uid: uid}
		} else {
			return nil, err
		}
	} else {
		return passwdC2Go(passwdC), nil
	}
}

// GetPasswdEntry wraps up `getpwent` system call
// It performs sequential scans of the records in the password file.
func GetPasswdEntry() []*Passwd {
	mutex.Lock()
	defer mutex.Unlock()
	var passwds []*Passwd

	// Restart scanning from the begging of the password file.
	C.setpwent()

	for {
		passwdC := C.getpwent()
		if passwdC == nil {
			break
		}
		passwd := passwdC2Go(passwdC)
		passwds = append(passwds, passwd)
	}

	// Call endpwent() is necessary so that any subsequent getpwent() call will
	// reopen the password file and start from the beginning.
	C.endpwent()

	return passwds
}
