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
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

func handle(s *Server, conn net.Conn) {
	defer conn.Close()
	defer log.Debugln("Connection from", conn.RemoteAddr().String(), "closed")
	log.Debugln("New connection from", conn.RemoteAddr().String())

	reader := bufio.NewReader(conn)
	request, err := handshake(s, conn, reader)
	if err != nil {
		log.Errorln("client:", conn.RemoteAddr().String(), "error:", err)
		return
	}
	if request == nil {
		return
	}

	if request.action == proxyActionConnection {
		var client, remoteAddr string
		if len(request.username) > 0 {
			client = fmt.Sprintf("%s(%s)", conn.RemoteAddr().String(), request.username)
		} else {
			client = conn.RemoteAddr().String()
		}
		if len(request.domain) > 0 {
			remoteAddr = fmt.Sprintf("%s:%d", request.domain, request.port)
		} else {
			remoteAddr = fmt.Sprintf("[%s]:%d", request.addr.String(), request.port)
		}

		log.Infof("%s connecting to %s", client, remoteAddr)

		err = proxy(s, conn, request)
		if err != nil {
			log.Debugf("%s get error from %s: %s", client, remoteAddr, err.Error())
		}
	}
}
