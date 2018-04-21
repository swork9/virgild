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

package socks

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

type handshakeSocks5AuthAnswer struct {
	version byte
	method  byte
}

type handshakeSocks5AuthUsernamePasswordAnswer struct {
	version byte
	status  byte
}

type handshakeSocks5Answer struct {
	version byte
	status  byte
	null    byte
}

func socks5SendAuthAnswer(conn net.Conn, method byte) {
	answer := &handshakeSocks5AuthAnswer{}
	answer.version = 0x05
	answer.method = method

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	conn.Write(buffer.Bytes())
}

func socks5SendAuthUsernamePasswordAnswer(conn net.Conn, status byte) {
	answer := &handshakeSocks5AuthUsernamePasswordAnswer{}
	answer.version = 0x01
	answer.status = status

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	conn.Write(buffer.Bytes())
}

func socks5SendAnswer(conn net.Conn, status byte, request *clientRequest) {
	answer := &handshakeSocks5Answer{}
	answer.version = 0x05
	answer.status = status
	answer.null = 0x00

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	if len(request.addr) == 4 {
		buffer.WriteByte(0x01)
		binary.Write(&buffer, binary.LittleEndian, request.addr)
	} else if len(request.domain) > 0 {
		domain := []byte(request.domain)
		domainLength := byte(len(request.domain))

		buffer.WriteByte(0x03)
		buffer.WriteByte(domainLength)
		binary.Write(&buffer, binary.LittleEndian, domain)
	} else if len(request.addr) == 16 {
		buffer.WriteByte(0x04)
		binary.Write(&buffer, binary.LittleEndian, request.addr)
	} else {
		tmpAddr := make([]byte, 4)
		buffer.WriteByte(0x01)
		binary.Write(&buffer, binary.LittleEndian, tmpAddr)
	}

	binary.Write(&buffer, binary.BigEndian, request.port)

	conn.Write(buffer.Bytes())
}

func socks5AuthUser(s *Server, conn net.Conn, reader *bufio.Reader) (string, error) {
	version, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	if version != 0x01 {
		return "", fmt.Errorf("socks5 client send unknown version for authentication method")
	}

	usernameLength, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	if usernameLength == 0x00 {
		return "", fmt.Errorf("socks5 client send zero length for username")
	}
	usernameBytes := make([]byte, usernameLength)
	err = binary.Read(reader, binary.LittleEndian, &usernameBytes)
	if err != nil {
		return "", err
	}

	passwordLength, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	if passwordLength == 0x00 {
		return "", fmt.Errorf("socks5 client send zero length for password")
	}
	passwordBytes := make([]byte, passwordLength)
	err = binary.Read(reader, binary.LittleEndian, &passwordBytes)
	if err != nil {
		return "", err
	}

	username := string(usernameBytes)
	password := string(passwordBytes)

	ok := false
	for _, method := range s.authMethods {
		ok, err = method.Check(username, password)
		if err != nil {
			log.Errorln("(auth)", err)
		}
		if ok {
			break
		}
	}
	if !ok {
		socks5SendAuthUsernamePasswordAnswer(conn, 0x01)
		return "", fmt.Errorf("socks5 client with username: \"%s\" and password: \"%s\" don't exists in our db", username, password)
	}

	socks5SendAuthUsernamePasswordAnswer(conn, 0x00)
	return username, nil
}

func handshakeSocks5AuthPart(s *Server, conn net.Conn, reader *bufio.Reader) (*clientRequest, error) {
	authMethodsCount, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if authMethodsCount == 0x00 {
		return nil, fmt.Errorf("socks5 client send zero count of authentication methods")
	}
	authMethods := make([]byte, authMethodsCount)
	err = binary.Read(reader, binary.LittleEndian, &authMethods)
	if err != nil {
		return nil, err
	}

	request := &clientRequest{}
	ok := false
	for _, i := range authMethods {
		if i == 0x00 && s.config.Server.AllowAnonymous {
			ok = true
			socks5SendAuthAnswer(conn, 0x00)

			break
		} else if i == 0x02 && len(s.authMethods) > 0 {
			ok = true
			socks5SendAuthAnswer(conn, 0x02)

			request.username, err = socks5AuthUser(s, conn, reader)
			if err != nil {
				return nil, err
			}

			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("socks5 client don't provide supported authentication methods")
	}

	return request, nil
}

func handshakeSocks5(s *Server, conn net.Conn, reader *bufio.Reader) (*clientRequest, error) {
	request, err := handshakeSocks5AuthPart(s, conn, reader)
	if err != nil {
		return nil, err
	}

	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != 0x05 {
		return nil, fmt.Errorf("socks5 client send unknown version for connection method")
	}

	command, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	if command == 0x01 {
		request.action = proxyActionConnection
	} else if command == 0x02 {
		if !s.config.Server.AllowTCPBind {
			socks5SendAnswer(conn, 0x02, request)
			return nil, fmt.Errorf("TCP binding disabled in config")
		}
		request.action = proxyActionTCPBind
	} else if command == 0x03 {
		if !s.config.Server.AllowUDPAssociation {
			socks5SendAnswer(conn, 0x02, request)
			return nil, fmt.Errorf("UDP association disabled in config")
		}
		request.action = proxyActionUDPAssociation
	} else {
		return nil, fmt.Errorf("socks5 client send unknown command")
	}

	// Skip reserved byte
	_, err = reader.ReadByte()
	if err != nil {
		return nil, err
	}

	addrType, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	if addrType == 0x01 {
		ip := make([]byte, 4)
		err = binary.Read(reader, binary.LittleEndian, &ip)
		if err != nil {
			return nil, err
		}

		request.addr = ip
	} else if addrType == 0x03 {
		domainLength, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}

		domain := make([]byte, domainLength)
		err = binary.Read(reader, binary.LittleEndian, &domain)
		if err != nil {
			return nil, err
		}

		request.domain = string(domain)
	} else if addrType == 0x04 {
		ip := make([]byte, 16)
		//var ip [16]byte
		err = binary.Read(reader, binary.LittleEndian, &ip)
		if err != nil {
			return nil, err
		}

		request.addr = ip
	} else {
		return nil, fmt.Errorf("socks5 client send unknown remote address type")
	}

	var port uint16
	err = binary.Read(reader, binary.BigEndian, &port)
	if err != nil {
		return nil, err
	}
	request.port = port

	socks5SendAnswer(conn, 0x00, request)
	return request, nil
}
