/**
 * Copyright (c) 2011 ~ 2014 Deepin, Inc.
 *               2013 ~ 2014 jouyouyun
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

package gzip

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path"
	"pkg.linuxdeepin.com/lib/utils"
)

func tarCompressFiles(files []string, dest string) error {
	dw, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer dw.Close()

	gw := gzip.NewWriter(dw)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, file := range files {
		var err error
		if utils.IsDir(file) {
			err = tarIterCompressDir(tw, file, "")
		} else {
			err = tarCompressFile(tw, file, "")
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func tarExtracte(src, destDir string) ([]string, error) {
	sr, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer sr.Close()

	gr, err := gzip.NewReader(sr)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var rets []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		file := path.Join(destDir, h.Name)
		rets = append(rets, file)
		err = os.MkdirAll(path.Dir(file), 0755)
		if err != nil {
			return nil, err
		}

		fw, err := os.OpenFile(file,
			os.O_CREATE|os.O_WRONLY,
			os.FileMode(h.Mode))
		if err != nil {
			return nil, err
		}

		//Error: too many open files
		//defer fw.Close()

		_, err = io.Copy(fw, tr)
		if err != nil {
			fw.Close()
			return nil, err
		}
		fw.Close()
	}

	return rets, nil
}

func tarIterCompressDir(tw *tar.Writer, dir, parent string) error {
	dr, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dr.Close()

	finfos, err := dr.Readdir(0)
	if err != nil {
		return err
	}

	parent = path.Join(parent, path.Base(dir))
	for _, finfo := range finfos {
		file := path.Join(dir, finfo.Name())

		var err error
		if finfo.IsDir() {
			err = tarIterCompressDir(tw, file, parent)
		} else {
			err = tarCompressFile(tw, file, parent)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func tarCompressFile(tw *tar.Writer, file, parent string) error {
	fr, err := os.Open(file)
	if err != nil {
		return err
	}
	defer fr.Close()

	finfo, err := fr.Stat()
	if err != nil {
		return err
	}

	h := new(tar.Header)
	h.Name = path.Join(parent, finfo.Name())
	h.Size = finfo.Size()
	h.Mode = int64(finfo.Mode())
	h.ModTime = finfo.ModTime()

	err = tw.WriteHeader(h)
	if err != nil {
		return err
	}

	_, err = io.Copy(tw, fr)
	if err != nil {
		return err
	}

	return nil
}
