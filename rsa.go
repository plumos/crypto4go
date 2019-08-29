package crypto4go

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

func packageData(originalData []byte, packageSize int) (r [][]byte) {
	var src = make([]byte, len(originalData))
	copy(src, originalData)

	r = make([][]byte, 0)
	if len(src) <= packageSize {
		return append(r, src)
	}
	for len(src) > 0 {
		var p = src[:packageSize]
		r = append(r, p)
		src = src[packageSize:]
		if len(src) <= packageSize {
			r = append(r, src)
			break
		}
	}
	return r
}

// RSAEncrypt 使用公钥 key 对数据 src 进行 RSA 加密
func RSAEncrypt(src, key []byte) ([]byte, error) {
	pub, err := ParsePublicKey(key)
	if err != nil {
		return nil, err
	}

	return RSAEncryptWithKey(src, pub)
}

// RSAEncryptWithKey 使用公钥 key 对数据 src 进行 RSA 加密
func RSAEncryptWithKey(src []byte, key *rsa.PublicKey) ([]byte, error) {
	var data = packageData(src, key.N.BitLen()/8-11)
	var cipher = make([]byte, 0, 0)

	for _, d := range data {
		var c, e = rsa.EncryptPKCS1v15(rand.Reader, key, d)
		if e != nil {
			return nil, e
		}
		cipher = append(cipher, c...)
	}

	return cipher, nil
}

// RSADecryptWithPKCS1 使用私钥 key 对数据 cipher 进行 RSA 解密，key 的格式为 pkcs1
func RSADecryptWithPKCS1(cipher, key []byte) ([]byte, error) {
	pri, err := ParsePKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}

	return RSADecryptWithKey(cipher, pri)
}

// RSADecryptWithPKCS1 使用私钥 key 对数据 cipher 进行 RSA 解密，key 的格式为 pkcs8
func RSADecryptWithPKCS8(cipher, key []byte) ([]byte, error) {
	pri, err := ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	return RSADecryptWithKey(cipher, pri)
}

// RSADecryptWithKey 使用私钥 key 对数据 cipher 进行 RSA 解密
func RSADecryptWithKey(cipher []byte, key *rsa.PrivateKey) ([]byte, error) {
	var data = packageData(cipher, key.PublicKey.N.BitLen()/8)
	var plainData = make([]byte, 0, 0)

	for _, d := range data {
		var p, e = rsa.DecryptPKCS1v15(rand.Reader, key, d)
		if e != nil {
			return nil, e
		}
		plainData = append(plainData, p...)
	}
	return plainData, nil
}

func RSASignWithPKCS1(src, key []byte, hash crypto.Hash) ([]byte, error) {
	pri, err := ParsePKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return RSASignWithKey(src, pri, hash)
}

func RSASignWithPKCS8(src, key []byte, hash crypto.Hash) ([]byte, error) {
	pri, err := ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return RSASignWithKey(src, pri, hash)
}

func RSASignWithKey(src []byte, key *rsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	var h = hash.New()
	h.Write(src)
	var hashed = h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
}

func RSAVerify(src, sig, key []byte, hash crypto.Hash) error {
	pub, err := ParsePublicKey(key)
	if err != nil {
		return err
	}
	return RSAVerifyWithKey(src, sig, pub, hash)
}

func RSAVerifyWithKey(src, sig []byte, key *rsa.PublicKey, hash crypto.Hash) error {
	var h = hash.New()
	h.Write(src)
	var hashed = h.Sum(nil)
	return rsa.VerifyPKCS1v15(key, hash, hashed, sig)
}
