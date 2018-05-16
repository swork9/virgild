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
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/swork9/virgild/models"
)

type socks4Client struct {
	server      *Server
	config      *models.Config
	conn        net.Conn
	useHostname bool

	command  byte
	port     uint16
	ip       net.IP
	userID   []byte
	hostname string
}

func (s *socks4Client) Read(reader *bufio.Reader) error {
	var err error
	if s.command, err = reader.ReadByte(); err != nil {
		return err
	}
	if err = binary.Read(reader, binary.BigEndian, &s.port); err != nil {
		return err
	}
	ip := make([]byte, 4)
	if err = binary.Read(reader, binary.LittleEndian, &ip); err != nil {
		return err
	}
	if s.userID, err = readUntilNullByte(reader, 256); err != nil {
		return err
	}

	if ip[0] == 0x00 && ip[1] == 0x00 && ip[2] == 0x00 && ip[3] != 0x00 {
		var t []byte
		if t, err = readUntilNullByte(reader, 256); err != nil {
			return err
		}

		s.hostname = string(t)
		s.useHostname = true
	} else {
		s.ip = ip
	}

	return nil
}

func (s *socks4Client) Answer(code byte) []byte {
	answer := &struct {
		null       byte
		result     byte
		ignorePort [2]byte
		ignoreIP   [4]byte
	}{}

	answer.null = 0x00
	answer.result = code

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	return buffer.Bytes()
}

func (s *socks4Client) AnswerBind(code byte, ip net.IP, port uint16) []byte {
	answer := &struct {
		null   byte
		result byte
	}{}

	answer.null = 0x00
	answer.result = code

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	binary.Write(&buffer, binary.BigEndian, port)
	binary.Write(&buffer, binary.LittleEndian, ip.To4())

	return buffer.Bytes()
}

func (s *socks4Client) Validate() error {
	if s.command == 0x01 {
	} else if s.command == 0x02 {
		if !s.config.Server.AllowTCPBind {
			s.conn.Write(s.Answer(0x5B))
			return fmt.Errorf("TCP binding disabled in config")
		}
	} else {
		return fmt.Errorf("socks4 client send unknown command")
	}

	return nil
}

func (s *socks4Client) Handshake(reader *bufio.Reader) error {
	var err error
	if err = s.Read(reader); err != nil {
		return err
	}
	if err = s.Validate(); err != nil {
		return err
	}

	return nil
}

func (s *socks4Client) Auth(reader *bufio.Reader, authMethods []models.AuthMethod) (*models.User, error) {
	// Socks4 don't support authentication (ident not what we want, huh)
	if !s.config.Server.AllowAnonymous {
		s.conn.Write(s.Answer(0x5B))
		return nil, fmt.Errorf("socks4 don't support authentication and anonymous access disabled in config")
	}

	return nil, nil
}

func (s *socks4Client) Request(reader *bufio.Reader) error {
	// For socks4 nothing to do.

	return nil
}

func (s *socks4Client) Work() error {
	var err error
	if s.command == 0x01 {
		// CONNECT
		var remoteAddr string
		if s.useHostname {
			remoteAddr = fmt.Sprintf("%s:%d", s.hostname, s.port)
		} else {
			remoteAddr = fmt.Sprintf("[%s]:%d", s.ip.String(), s.port)
		}

		log.Infof("%s connecting to %s", s.conn.RemoteAddr().String(), remoteAddr)

		var remote net.Conn
		if s.useHostname {
			if remote, err = connectHostname(s.server, nil, s.hostname, s.port); err != nil {
				s.conn.Write(s.Answer(0x5B))
				return err
			}
		} else {
			if remote, err = connectIP(s.server, nil, s.ip, s.port); err != nil {
				s.conn.Write(s.Answer(0x5B))
				return err
			}
		}

		s.conn.Write(s.Answer(0x5A))

		go proxyChannel(s.config, s.conn, remote)
		proxyChannel(s.config, remote, s.conn)

		return nil
	} else if s.command == 0x02 {
		// TCP BIND
		if s.config.Server.TCPBindAddrIsHostname {
			s.conn.Write(s.Answer(0x5B))
			return fmt.Errorf("socks4 don't support tcp binding on hostname, please, use socks5 or change your config")
		} else if len(s.config.Server.TCPBindAddrIP) != 4 {
			s.conn.Write(s.Answer(0x5B))
			return fmt.Errorf("socks4 don't support tcp binding on ipv6, please, use socks5 or change your config")
		}

		port, err := s.server.GetTCPPort()
		if err != nil {
			s.conn.Write(s.Answer(0x5B))
			return err
		}
		defer s.server.FreeTCPPort(port)

		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.config.Server.TCPBindAddrIP.String(), port))
		if err != nil {
			s.conn.Write(s.Answer(0x5B))
			return err
		}
		defer listener.Close()

		tcpListener := listener.(*net.TCPListener)
		tcpListener.SetDeadline(time.Now().Add(time.Duration(s.config.Server.Timeout) * time.Second))

		log.Infof("%s request tcp bind on %s:%d", s.conn.RemoteAddr().String(), s.config.Server.TCPBindAddrIP.String(), port)
		s.conn.Write(s.AnswerBind(0x5A, s.config.Server.TCPBindAddrIP, uint16(port)))

		remote, err := listener.Accept()
		if err != nil {
			s.conn.Write(s.AnswerBind(0x5B, s.config.Server.TCPBindAddrIP, uint16(port)))
			return err
		}
		defer remote.Close()

		remoteAddr := remote.RemoteAddr().(*net.TCPAddr)
		log.Infof("%s get new tcp connection from %s", s.conn.RemoteAddr().String(), remote.RemoteAddr().String())
		s.conn.Write(s.AnswerBind(0x5A, remoteAddr.IP, uint16(remoteAddr.Port)))

		go proxyChannel(s.config, s.conn, remote)
		proxyChannel(s.config, remote, s.conn)

		return nil
	}

	return fmt.Errorf("socks4 client send unknown command and somehow it was validated")
}
