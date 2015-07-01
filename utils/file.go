/**
 * Copyright (c) 2011 ~ 2013 Deepin, Inc.
 *               2011 ~ 2013 jouyouyun
 *
 * Author:      jouyouyun <jouyouwen717@gmail.com>
 * Maintainer:  jouyouyun <jouyouwen717@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 **/

package utils

import (
	"fmt"
	"io"
	"os"
	"path"
)

func CopyFile(src, dest string) (err error) {
	if dest == src {
		return nil
	}

	sf, err := os.Open(src)
	if err != nil {
		return
	}
	defer sf.Close()

	df, err := os.Create(dest)
	if err != nil {
		return
	}
	defer df.Close()

	_, err = io.Copy(df, sf)
	return
}

func CopyDir(src, dest string) error {
	sInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return iterCopyDir(src, dest, sInfo.Mode())
}

func MoveDir(src, dest string) error {
	if !IsDir(src) {
		return fmt.Errorf("%q not a dir", src)
	}

	err := CopyDir(src, dest)
	if err != nil {
		return err
	}

	return os.RemoveAll(src)
}

func MoveFile(src, dest string) error {
	if IsDir(src) {
		return fmt.Errorf("%q not a file", src)
	}

	err := CopyFile(src, dest)
	if err != nil {
		return err
	}

	return os.RemoveAll(src)
}

func IsFileExist(path string) bool {
	// if is uri path, ensure it decoded
	path = DecodeURI(path)
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

func IsDir(path string) bool {
	// if is uri path, ensure it decoded
	path = DecodeURI(path)
	f, err := os.Stat(path)
	if err != nil {
		return false
	}
	return f.IsDir()
}

func IsSymlink(path string) bool {
	// if is uri path, ensure it decoded
	path = DecodeURI(path)
	f, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if f.Mode()&os.ModeSymlink == os.ModeSymlink {
		return true
	}
	return false
}

func EnsureDirExist(path string) error {
	return os.MkdirAll(path, 0755)
}

func EnsureDirExistWithPerm(path string, perm os.FileMode) error {
	// TODO if path exists with wrong perm, fix it
	return os.MkdirAll(path, perm)
}

func iterCopyDir(src, dest string, mode os.FileMode) error {
	sr, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sr.Close()

	finfos, err := sr.Readdir(0)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dest, mode)
	if err != nil {
		return err
	}

	for _, fi := range finfos {
		sTmp := path.Join(src, fi.Name())
		dTmp := path.Join(dest, fi.Name())

		var err error
		if fi.IsDir() {
			err = iterCopyDir(sTmp, dTmp, fi.Mode())
		} else {
			err = CopyFile(sTmp, dTmp)
		}

		if err != nil {
			return err
		}
	}

	return nil
}
