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
	"net"

	log "github.com/sirupsen/logrus"

	"virgild/models"
)

func handle(s *Server, conn net.Conn) {
	defer conn.Close()
	defer log.Debugln("Connection from", conn.RemoteAddr().String(), "closed")
	log.Debugln("New connection from", conn.RemoteAddr().String())

	reader := bufio.NewReader(conn)
	proxy, err := getProxyClientVersion(s, conn, reader)
	if err != nil {
		log.Errorln("client:", conn.RemoteAddr().String(), "version error:", err)
		return
	}

	if err = proxy.Handshake(reader); err != nil {
		log.Errorln("client:", conn.RemoteAddr().String(), "handshake error:", err)
		return
	}

	var user *models.User
	if user, err = proxy.Auth(reader, s.authMethods); err != nil {
		log.Errorln("client:", conn.RemoteAddr().String(), "auth error:", err)
		return
	}

	// Check for subnets rules
	if err = checkSubnetsRules(s, user, conn); err != nil {
		log.Errorln("client:", conn.RemoteAddr().String(), "security error:", err)
		return
	}

	if err = proxy.Request(reader); err != nil {
		log.Errorln("client:", conn.RemoteAddr().String(), "request error:", err)
		return
	}

	if err = proxy.Work(); err != nil {
		log.Errorln("client:", conn.RemoteAddr().String(), "error:", err)
		return
	}
}
