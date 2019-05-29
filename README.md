# 使用公钥加密

```go

msg := []byte("加密的内容")

priv, err := rsa_pfx.ParseFile("./test.pfx", keyPassword)
if err != nil {
    fmt.Printf("Error PaseFile:%s", err.Error())
    return
}

encryptData, err := rsa_pfx.PubEncrypt(&priv.(*rsa.PrivateKey).PublicKey, msg)
if err != nil {
    fmt.Printf("Error PubEncrypt:%s", err.Error())
    return
}

// base64编码
base64Data := base64.StdEncoding.EncodeToString(encryptData)
```

# 使用私钥解密

```go

priv, err := rsa_pfx.ParseFile("./test.pfx", keyPassword)
if err != nil {
    fmt.Printf("Error PaseFile:%s", err.Error())
    return
}

// base64解码
encryptData, err := base64.StdEncoding.DecodeString(encryptData)
if err != nil {
    fmt.Printf("Error DecodeString:%s", err.Error())
    return
}

decryptData, err := rsa_pfx.PriDecrypt(priv.(*rsa.PrivateKey), encryptData)
if err != nil {
    fmt.Printf("Error rsa_pfx.PriDecrypt:%s",err.Error())
    return
}

```
