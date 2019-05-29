/**
 * Creator: hevi
 * Time: 2019-05-29 15:34
 * Description: 私钥加密，私钥解密
 */

package rsa_pfx

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"io/ioutil"
)

// 私钥解密
func PriDecrypt(pri *rsa.PrivateKey, data []byte) ([]byte, error) {
	w := bytes.NewBuffer(nil)

	r := bytes.NewReader(data)

	k := (pri.N.BitLen() + 7) / 8

	buf := make([]byte, k)
	var b []byte
	var err error
	size := 0
	for {
		size, err = r.Read(buf)
		if err != nil {
			if err == io.EOF {
				return ioutil.ReadAll(w)
			}
			return nil, err
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}

		b, err = rsa.DecryptPKCS1v15(rand.Reader, pri, b)

		if err != nil {
			return nil, err
		}
		if _, err = w.Write(b); err != nil {
			return nil, err
		}
	}
	return nil, nil
}
