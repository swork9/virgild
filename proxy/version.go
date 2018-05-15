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

package proxy

import (
	"bufio"
	"fmt"
	"net"

	"github.com/swork9/virgild/models"
)

func getProxyClientVersion(s *Server, conn net.Conn, reader *bufio.Reader) (models.ProxyClient, error) {
	socksVersion, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	if socksVersion == 0x04 {
		return &socks4Client{server: s, config: s.config, conn: conn}, nil
	} else if socksVersion == 0x05 {
		return &socks5Client{server: s, config: s.config, conn: conn}, nil
		// Looks like it's http CONNECT, so try it.
	} else if socksVersion == 'C' {
		return &httpClient{server: s, config: s.config, conn: conn}, nil
	} else {
		return nil, fmt.Errorf("client send unknown socks version")
	}
}
