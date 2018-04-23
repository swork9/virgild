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
	"fmt"
	"net"
	"time"

	"github.com/swork9/virgild/models"
)

func connectIP(ip net.IP, port uint16) (net.Conn, error) {
	c, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: ip, Port: int(port)})
	if err != nil {
		return nil, err
	}

	return c, nil
}

func connectHostname(host string, port uint16) (net.Conn, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		c, err := connectIP(ip, port)
		if err == nil {
			return c, nil
		}
	}

	return nil, fmt.Errorf("destination host unreachable")
}

func proxyChannel(config *models.Config, from net.Conn, to net.Conn) {
	defer from.Close()
	defer to.Close()

	var ret int
	var err error
	buffer := make([]byte, config.Server.Buffer)

	timeoutDuration := time.Duration(config.Server.Timeout) * time.Second

	for {
		from.SetReadDeadline(time.Now().Add(timeoutDuration))

		ret, err = from.Read(buffer)
		if err != nil {
			return
		}

		_, err = to.Write(buffer[0:ret])
		if err != nil {
			return
		}
	}
}
