/**
 * Creator: hevi
 * Time: 2019-05-29 15:24
 * Description: RSA 公钥加密或公钥解密
 */

package rsa_pfx

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"io/ioutil"
)

// 公钥加密
func PubEncrypt(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	out := bytes.NewBuffer(nil)

	// 内容分块读取
	in := bytes.NewReader(msg)

	// 每块的字节长度
	k := (pub.N.BitLen()+7)/8 - 11

	buf := make([]byte, k)
	var b []byte
	var err error
	size := 0

	for {
		// 将k长度的字节数据读进bug
		size, err = in.Read(buf)
		if err != nil {
			if err == io.EOF {
				return ioutil.ReadAll(out)
			}
			return nil, err
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}

		// 对每块单独加密
		b, err = rsa.EncryptPKCS1v15(rand.Reader, pub, b)
		if err != nil {
			return nil, err
		}

		if _, err = out.Write(b); err != nil {
			return nil, err
		}
	}

	return nil, nil
}
