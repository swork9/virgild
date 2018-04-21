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
)

type handshakeSocks4Answer struct {
	null    byte
	result  byte
	ignore0 [2]byte
	ignore1 [4]byte
}

func socks4SendAnswer(conn net.Conn, code byte) {
	answer := &handshakeSocks4Answer{}
	answer.null = 0x00
	answer.result = code

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	conn.Write(buffer.Bytes())
}

func handshakeSocks4(s *Server, conn net.Conn, reader *bufio.Reader) (*clientRequest, error) {
	if !s.config.Server.AllowAnonymous {
		socks4SendAnswer(conn, 0x5B)
		return nil, fmt.Errorf("socks4 don't support authentication and anonymous access disabled in config")
	}

	command, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	request := &clientRequest{}
	if command == 0x01 {
		request.action = proxyActionConnection
	} else if command == 0x02 {
		if !s.config.Server.AllowTCPBind {
			socks4SendAnswer(conn, 0x5B)
			return nil, fmt.Errorf("TCP binding disabled in config")
		}
		request.action = proxyActionTCPBind
	} else {
		return nil, fmt.Errorf("socks4 client send unknown command")
	}

	var port uint16
	err = binary.Read(reader, binary.BigEndian, &port)
	if err != nil {
		return nil, err
	}
	request.port = port

	ip := make([]byte, 4)
	err = binary.Read(reader, binary.LittleEndian, &ip)
	if err != nil {
		return nil, err
	}

	// Skip username
	ok := false
	var tmp byte
	for i := 0; i < 256; i++ {
		tmp, err = reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if tmp == 0x00 {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("socks4 username more then 256 bytes, aborting")
	}

	// Check for socks4a
	if ip[0] == 0x00 && ip[1] == 0x00 && ip[2] == 0x00 && ip[3] != 0x00 {
		ok = false
		var buffer bytes.Buffer
		for i := 0; i < 256; i++ {
			tmp, err = reader.ReadByte()
			if err != nil {
				return nil, err
			}
			if tmp == 0x00 {
				ok = true
				break
			}
			buffer.WriteByte(tmp)
		}
		if !ok {
			return nil, fmt.Errorf("socks4a domain name more then 256 bytes, aborting")
		}

		// Remove 0x00
		request.domain = string(buffer.Bytes())
	} else {
		request.addr = ip
	}

	socks4SendAnswer(conn, 0x5A)
	return request, nil
}
