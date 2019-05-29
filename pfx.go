/**
 * Creator: hevi
 * Time: 2019-05-29 12:14
 * Description: 描述该文件
 */

package rsa_pfx

import (
	"crypto/rsa"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
)

func ParseFile(filename, pwd string) (interface{}, error) {
	fileBuf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	priv, _, err := pkcs12.Decode(fileBuf, pwd)
	if err != nil {
		return nil, err
	}

	if err := priv.(*rsa.PrivateKey).Validate(); err != nil {
		return nil, err
	}

	return priv, nil
}
