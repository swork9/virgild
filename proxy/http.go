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
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	"virgild/models"

	log "github.com/sirupsen/logrus"
)

type httpClient struct {
	server *Server
	config *models.Config
	conn   net.Conn
	user   *models.User

	command  string
	hostname string
	port     int

	headers   []byte
	proxyAuth string
}

func (h *httpClient) Answer(status string) []byte {
	return []byte("HTTP/1.1 " + status + "\r\nProxy-Agent: virgild\r\n\r\n")
}

func (h *httpClient) ReadCommand(reader *bufio.Reader) error {
	var buffer []byte
	var err error
	if buffer, err = reader.ReadBytes(' '); err != nil {
		return err
	}
	h.command = string(buffer[0 : len(buffer)-1])

	if buffer, err = reader.ReadBytes(' '); err != nil {
		return err
	}
	h.hostname = string(buffer[0 : len(buffer)-1])

	if _, err = reader.ReadBytes('\n'); err != nil {
		return err
	}

	return nil
}

func (h *httpClient) ReadHeaders(reader *bufio.Reader) error {
	var buffer []byte
	var line string
	var err error

	for {
		if buffer, err = reader.ReadBytes('\n'); err != nil {
			return err
		}
		if len(buffer) <= 2 {
			break
		}

		line = string(buffer[0 : len(buffer)-2])
		if strings.HasPrefix(strings.ToLower(line), "proxy-authorization: ") {
			h.proxyAuth = line[21:]
		} else {
			h.headers = append(h.headers, buffer...)
		}
	}

	h.headers = append(h.headers, '\r')
	h.headers = append(h.headers, '\n')

	return nil
}

func (h *httpClient) Handshake(reader *bufio.Reader) error {
	var err error
	if err = h.ReadCommand(reader); err != nil {
		return err
	}
	if err = h.ReadHeaders(reader); err != nil {
		return err
	}

	if h.command == "CONNECT" {
		tmp := strings.SplitN(h.hostname, ":", 2)
		if len(tmp) != 2 {
			return fmt.Errorf("http client send wrong host and/or port")
		}

		h.hostname = tmp[0]
		if h.port, err = strconv.Atoi(tmp[1]); err != nil {
			return err
		}
	} else {
		tmp := strings.SplitN(h.hostname, "/", 4)
		if len(tmp) < 4 {
			return fmt.Errorf("http client send wrong hostname")
		}

		h.hostname = tmp[2]
		h.port = 80

		h.headers = append([]byte(fmt.Sprintf("%s /%s HTTP/1.1\r\n", h.command, tmp[3])), h.headers...)
	}

	return nil
}

func (h *httpClient) GetUserPassword() (string, string, error) {
	if len(h.proxyAuth) == 0 {
		return "", "", fmt.Errorf("http client don't provide authentication credentials")
	}

	if strings.HasSuffix(strings.ToLower(h.proxyAuth), "basic ") {
		return "", "", fmt.Errorf("http client authentication not looks like \"Basic\"")
	}

	baseDecoded, err := base64.StdEncoding.DecodeString(h.proxyAuth[6:])
	if err != nil {
		return "", "", err
	}

	credentials := strings.SplitN(string(baseDecoded), ":", 2)
	if len(credentials) != 2 {
		return "", "", fmt.Errorf("http client authentication credentials can't be extracted")
	}

	return credentials[0], credentials[1], nil
}

func (h *httpClient) Auth(reader *bufio.Reader, authMethods []models.AuthMethod) (*models.User, error) {
	username, password, err := h.GetUserPassword()
	if err != nil {
		if !h.config.Server.AllowAnonymous {
			h.conn.Write(h.Answer("407 Proxy Authentication Required\r\nProxy-Authenticate: Basic"))
			return nil, err
		}
	} else {
		ok := false
		for _, method := range authMethods {
			ok, err = method.Check(username, password)
			if err != nil {
				log.Errorln("(auth)", err)
			}
			if ok {
				h.user = &models.User{Name: username}
				return h.user, nil
			}
		}

		if !ok {
			h.conn.Write(h.Answer("403 Forbidden"))
			return nil, fmt.Errorf("socks5 client with username: \"%s\" and password: \"%s\" don't exists in our db", username, password)
		}
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
	if remote, err = connectHostname(h.server, h.user, h.hostname, uint16(h.port)); err != nil {
		h.conn.Write(h.Answer("503 Service Unavailable"))
		return err
	}

	if h.command == "CONNECT" {
		h.conn.Write(h.Answer("200 Connection Established"))
	} else {
		remote.Write(h.headers)
	}

	go proxyChannel(h.config, h.conn, remote)
	proxyChannel(h.config, remote, h.conn)

	return nil
}
