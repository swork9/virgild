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
	"io/ioutil"
	"strings"
)

type AuthPlain struct {
	file       string
	hashMethod string
	users      map[string]string
}

func (a *AuthPlain) GetName() string {
	return "plain"
}

func (a *AuthPlain) Init() error {
	data, err := ioutil.ReadFile(a.file)
	if err != nil {
		return err
	}

	a.users = map[string]string{}
	for _, i := range strings.Split(string(data), "\n") {
		s := strings.SplitN(i, ":", 2)
		if len(s) == 2 && len(s[0]) > 0 && len(s[1]) > 0 {
			a.users[s[0]] = s[1]
		}
	}

	return nil
}

func (a *AuthPlain) Close() error {
	return nil
}

func (a *AuthPlain) Check(username, password string) (bool, error) {
	hashedPassword, ok := a.users[username]
	if !ok {
		return false, nil
	}

	var hasher hash.Hash
	if a.hashMethod == "md5" {
		hasher = md5.New()
	} else if a.hashMethod == "sha256" {
		hasher = sha256.New()
	} else if a.hashMethod == "sha512" {
		hasher = sha512.New()
	} else {
		return false, fmt.Errorf("plain auth don't support hash method:", a.hashMethod)
	}

	hasher.Write([]byte(password))
	check := hex.EncodeToString(hasher.Sum(nil))
	if hashedPassword == check {
		return true, nil
	}

	return false, nil
}

func NewAuthPlain(file, hashMethod string) (*AuthPlain, error) {
	auth := &AuthPlain{file: file, hashMethod: hashMethod, users: map[string]string{}}

	return auth, nil
}
