package crypto4go

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"golang.org/x/crypto/pbkdf2"
	"hash"
)

const (
	kPKCS5SaltLen      = 8
	kPKCS5DefaultIter  = 2048
	kPKCS5DefaultMagic = "Salted__"
	kEVPMaxIvLen       = 16
)

func randBytes(length int) (data []byte, err error) {
	data = make([]byte, length)
	_, err = rand.Read(data)
	return data, err
}

func AESCBCEncryptWithSalt(data, key []byte, iterCount int, magic string, h func() hash.Hash) ([]byte, error) {
	return AESEncryptWithSalt(data, key, iterCount, magic, h, AESCBCEncrypt)
}

func AESCBCDecryptWithSalt(data, key []byte, iterCount int, magic string, h func() hash.Hash) ([]byte, error) {
	return AESDecryptWithSalt(data, key, iterCount, magic, h, AESCBCDecrypt)
}

func AESEncryptWithSalt(data, key []byte, iterCount int, magic string, h func() hash.Hash, f func(data, key, iv []byte) (dst []byte, err error)) (dst []byte, err error) {
	if iterCount <= 0 {
		iterCount = kPKCS5DefaultIter
	}

	if h == nil {
		h = md5.New
	}

	var salt, _ = randBytes(kPKCS5SaltLen)
	var sKey = pbkdf2.Key(key, salt, iterCount, len(key), h)
	var sIV = pbkdf2.Key(sKey, salt, iterCount, kEVPMaxIvLen, h)

	dst, err = f(data, sKey, sIV)

	dst = append(salt, dst...)
	dst = append([]byte(magic), dst...)

	return dst, err
}

func AESDecryptWithSalt(data, key []byte, iterCount int, magic string, h func() hash.Hash, f func(ciphertext, key, iv []byte) ([]byte, error)) (dst []byte, err error) {
	if iterCount <= 0 {
		iterCount = kPKCS5DefaultIter
	}

	if h == nil {
		h = md5.New
	}

	//if len(data) <= len(magic) + kPKCS5SaltLen {
	//	return nil, errors.New("Error")
	//}

	var salt = data[len(magic) : len(magic)+kPKCS5SaltLen]
	var sKey = pbkdf2.Key(key, salt, iterCount, len(key), h)
	var sIV = pbkdf2.Key(sKey, salt, iterCount, kEVPMaxIvLen, h)

	dst, err = f(data[len(magic)+kPKCS5SaltLen:], sKey, sIV)

	return dst, err
}

// AESCBCEncrypt 由key的长度决定是128, 192 还是 256
func AESCBCEncrypt(data, key, iv []byte) ([]byte, error) {
	var block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var blockSize = block.BlockSize()
	iv = iv[:blockSize]

	var src = PKCS7Padding(data, blockSize)
	var dst = make([]byte, len(src))

	var mode = cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(dst, src)
	return dst, nil
}

func AESCBCDecrypt(data, key, iv []byte) ([]byte, error) {
	var block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var blockSize = block.BlockSize()
	iv = iv[:blockSize]

	var dst = make([]byte, len(data))

	var mode = cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, data)
	dst = PKCS7UnPadding(dst)
	return dst, nil
}

func AESCFBEncrypt(data, key, iv []byte) ([]byte, error) {
	var block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var blockSize = block.BlockSize()
	iv = iv[:blockSize]

	var dst = make([]byte, len(data))

	var mode = cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(dst, data)
	return dst, nil
}

func AESCFBDecrypt(data, key, iv []byte) ([]byte, error) {
	var block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var blockSize = block.BlockSize()
	iv = iv[:blockSize]

	var dst = make([]byte, len(data))

	var mode = cipher.NewCFBDecrypter(block, iv)
	mode.XORKeyStream(dst, data)
	return dst, nil
}
