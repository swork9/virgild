/*MIT License

Copyright (c) 2018 Станислав (swork91@mail.ru)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

package auth

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
)

type hashType int

const (
	hashMD5 hashType = iota
	hashSHA256
	hashSHA512
)

type authHasher struct {
	hashMethod hashType
}

func (a *authHasher) Hash(data string) string {
	var hasher hash.Hash
	if a.hashMethod == hashMD5 {
		hasher = md5.New()
	} else if a.hashMethod == hashSHA256 {
		hasher = sha256.New()
	} else if a.hashMethod == hashSHA512 {
		hasher = sha512.New()
	} else {
		return ""
	}

	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

func newHasher(hashMethod string) (*authHasher, error) {
	if hashMethod == "md5" {
		return &authHasher{hashMD5}, nil
	} else if hashMethod == "sha256" {
		return &authHasher{hashSHA256}, nil
	} else if hashMethod == "sha512" {
		return &authHasher{hashSHA512}, nil
	} else {
		return nil, fmt.Errorf("auth don't support hash method:", hashMethod)
	}
}
