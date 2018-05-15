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
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/swork9/virgild/models"
)

type httpClient struct {
	server *Server
	config *models.Config
	conn   net.Conn
	user   *models.User

	hostname string
	port     int
	headers  map[string]string
}

func (h *httpClient) Answer(status string) []byte {
	return []byte("HTTP/1.1 " + status + "\r\nProxy-Agent: virgild\r\n\r\n")
}

func (h *httpClient) Handshake(reader *bufio.Reader) error {
	if !h.config.Server.AllowHTTPConnect {
		return fmt.Errorf("HTTP CONNECT disabled in config")
	}
	h.headers = map[string]string{}

	firstLine := false
	var line []byte
	var n byte
	var err error
	for {
		line, err = reader.ReadBytes('\r')
		if err != nil {
			return err
		}
		// Remove '\r' from slice
		line = line[0 : len(line)-1]
		fmt.Println("DEBUG:", string(line), len(line))

		n, err = reader.ReadByte()
		if err != nil {
			return err
		}

		if n != '\n' {
			return fmt.Errorf("http client send wrong new line byte")
		}

		if len(line) == 0 {
			break
		}

		if firstLine {
			header := strings.SplitN(string(line), ": ", 2)
			if len(header) != 2 {
				continue
			}

			h.headers[header[0]] = header[1]
			fmt.Println("HEADER:", header)
		} else {
			connect := strings.SplitN(string(line), " ", 3)
			if len(connect) != 3 {
				return fmt.Errorf("http client send wrong CONNECT header")
			}

			// Yes, it's really ugly
			if connect[0] != "ONNECT" {
				return fmt.Errorf("http client send wrong http command")
			}

			host := strings.SplitN(connect[1], ":", 2)
			if len(host) != 2 {
				return fmt.Errorf("http client send wrong host and port")
			}

			h.hostname = host[0]
			h.port, err = strconv.Atoi(host[1])
			if err != nil {
				return err
			}

			firstLine = true
		}
	}

	if len(h.hostname) == 0 || h.port == 0 {
		return fmt.Errorf("http client send empty host and port")
	}

	fmt.Println(h.headers)
	fmt.Println(h.hostname)
	fmt.Println(h.port)

	return nil
}

func (h *httpClient) Auth(reader *bufio.Reader, authMethods []models.AuthMethod) (*models.User, error) {
	if !h.config.Server.AllowAnonymous {
		h.conn.Write(h.Answer("403 Forbidden"))
		return nil, fmt.Errorf("http don't support authentication and anonymous access disabled in config")
	}

	return nil, nil
}

func (h *httpClient) Request(reader *bufio.Reader) error {
	return nil
}

func (h *httpClient) Work() error {
	var client string
	if h.user != nil {
		client = fmt.Sprintf("%s(%s)", h.conn.RemoteAddr().String(), h.user.Name)
	} else {
		client = h.conn.RemoteAddr().String()
	}

	log.Infof("%s connecting to %s:%d", client, h.hostname, h.port)

	var err error
	var remote net.Conn
	if remote, err = connectHostname(h.hostname, uint16(h.port)); err != nil {
		h.conn.Write(h.Answer("503 Service Unavailable"))
		return err
	}

	h.conn.Write(h.Answer("200 Connection Established"))

	go proxyChannel(h.config, h.conn, remote)
	proxyChannel(h.config, remote, h.conn)

	return nil
}
