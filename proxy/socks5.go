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

	"virgild/models"
)

type socks5Client struct {
	server *Server
	config *models.Config
	conn   net.Conn
	user   *models.User

	handshake socks5Handshake
	auth      socks5Auth
	request   socks5Request
}

type socks5Handshake struct {
	authMethodsCount byte
	authMethods      []byte
}

type socks5Auth struct {
	version  byte
	username string
	password string
}

type socks5Request struct {
	version  byte
	command  byte
	reserved byte
	addrType byte

	ip          net.IP
	hostname    string
	useHostname bool

	port uint16
}

func (s *socks5Handshake) Read(reader *bufio.Reader) error {
	var err error
	if s.authMethodsCount, s.authMethods, err = readNBytes(reader); err != nil {
		return err
	}

	return nil
}

func (s *socks5Handshake) Answer(authMethod byte) []byte {
	answer := struct {
		version    byte
		authMethod byte
	}{}

	answer.version = 0x05
	answer.authMethod = authMethod

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	return buffer.Bytes()
}

func (s *socks5Auth) Read(reader *bufio.Reader) error {
	var err error
	if s.version, err = reader.ReadByte(); err != nil {
		return err
	}

	var t []byte
	if _, t, err = readNBytes(reader); err != nil {
		return err
	}
	s.username = string(t)

	if _, t, err = readNBytes(reader); err != nil {
		return err
	}
	s.password = string(t)

	return nil
}

func (s *socks5Auth) Answer(result byte) []byte {
	answer := struct {
		version byte
		result  byte
	}{}

	answer.version = 0x01
	answer.result = result

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	return buffer.Bytes()
}

func (s *socks5Request) Read(reader *bufio.Reader) error {
	var err error
	if s.version, err = reader.ReadByte(); err != nil {
		return err
	}
	if s.command, err = reader.ReadByte(); err != nil {
		return err
	}
	if s.reserved, err = reader.ReadByte(); err != nil {
		return err
	}
	if s.addrType, err = reader.ReadByte(); err != nil {
		return err
	}

	if s.addrType == 0x01 {
		ip := make([]byte, 4)
		if err = binary.Read(reader, binary.LittleEndian, &ip); err != nil {
			return err
		}
		s.ip = ip
	} else if s.addrType == 0x03 {
		var t []byte
		if _, t, err = readNBytes(reader); err != nil {
			return err
		}
		s.hostname = string(t)
		s.useHostname = true
	} else if s.addrType == 0x04 {
		ip := make([]byte, 16)
		if err = binary.Read(reader, binary.LittleEndian, &ip); err != nil {
			return err
		}
		s.ip = ip
	} else {
		return fmt.Errorf("socks5 client send unknown address type")
	}

	if err = binary.Read(reader, binary.BigEndian, &s.port); err != nil {
		return err
	}

	return nil
}

func (s *socks5Request) Answer(result byte) []byte {
	answer := struct {
		version  byte
		result   byte
		reserved byte
	}{}

	answer.version = 0x05
	answer.result = result
	answer.reserved = 0x00

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	if s.useHostname {
		t := []byte(s.hostname)
		tLength := byte(len(t))

		buffer.WriteByte(0x03)
		buffer.WriteByte(tLength)
		binary.Write(&buffer, binary.LittleEndian, t)
	} else if s.ip.To4() == nil {
		buffer.WriteByte(0x04)
		binary.Write(&buffer, binary.LittleEndian, s.ip.To16())
	} else {
		buffer.WriteByte(0x01)
		binary.Write(&buffer, binary.LittleEndian, s.ip.To4())
	}

	binary.Write(&buffer, binary.BigEndian, s.port)

	return buffer.Bytes()
}

func (s *socks5Request) AnswerBindIP(version byte, result byte, ip net.IP, port uint16) []byte {
	answer := struct {
		version  byte
		result   byte
		reserved byte
	}{}

	answer.version = version
	answer.result = result
	answer.reserved = 0x00

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	if ip.To4() == nil {
		buffer.WriteByte(0x04)
		binary.Write(&buffer, binary.LittleEndian, ip.To16())
	} else {
		buffer.WriteByte(0x01)
		binary.Write(&buffer, binary.LittleEndian, ip.To4())
	}

	binary.Write(&buffer, binary.BigEndian, port)

	return buffer.Bytes()
}

func (s *socks5Request) AnswerBindHostname(version byte, result byte, hostname string, port uint16) []byte {
	answer := struct {
		version  byte
		result   byte
		reserved byte
	}{}

	answer.version = version
	answer.result = result
	answer.reserved = 0x00

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.LittleEndian, answer)

	t := []byte(hostname)
	tLength := byte(len(t))

	buffer.WriteByte(0x03)
	buffer.WriteByte(tLength)
	binary.Write(&buffer, binary.LittleEndian, t)

	binary.Write(&buffer, binary.BigEndian, port)

	return buffer.Bytes()
}

func (s *socks5Client) Handshake(reader *bufio.Reader) error {
	var err error
	if err = s.handshake.Read(reader); err != nil {
		return err
	}

	return nil
}

func (s *socks5Client) Auth(reader *bufio.Reader, authMethods []models.AuthMethod) (*models.User, error) {
	for _, i := range s.handshake.authMethods {
		if i == 0x00 && s.config.Server.AllowAnonymous {
			s.conn.Write(s.handshake.Answer(0x00))

			return nil, nil
		} else if i == 0x02 && len(authMethods) > 0 {
			s.conn.Write(s.handshake.Answer(0x02))

			var err error
			if err = s.auth.Read(reader); err != nil {
				return nil, err
			}

			ok := false
			for _, method := range authMethods {
				ok, err = method.Check(s.auth.username, s.auth.password)
				if err != nil {
					log.Errorln("(auth)", err)
				}
				if ok {
					s.conn.Write(s.auth.Answer(0x00))
					s.user = &models.User{Name: s.auth.username}
					return s.user, nil
				}
			}

			if !ok {
				s.conn.Write(s.auth.Answer(0x01))
				return nil, fmt.Errorf("socks5 client with username: \"%s\" and password: \"%s\" don't exists in our db", s.auth.username, s.auth.password)
			}
		}
	}

	s.conn.Write(s.handshake.Answer(0xFF))
	return nil, fmt.Errorf("socks5 client don't provide supported authentication methods")
}

func (s *socks5Client) Request(reader *bufio.Reader) error {
	var err error
	if err = s.request.Read(reader); err != nil {
		return err
	}

	if s.request.version != 0x05 {
		return fmt.Errorf("socks5 client send wrong request version")
	}

	if s.request.command == 0x01 {
	} else if s.request.command == 0x02 {
		if !s.config.Server.AllowTCPBind {
			s.conn.Write(s.request.Answer(0x02))
			return fmt.Errorf("TCP binding disabled in config")
		}
	} else if s.request.command == 0x03 {
		if !s.config.Server.AllowUDPAssociation {
			s.conn.Write(s.request.Answer(0x02))
			return fmt.Errorf("UDP association disabled in config")
		}
	} else {
		return fmt.Errorf("socks5 client send unknown command")
	}

	return nil
}

func (s *socks5Client) Work() error {
	var client string
	if s.user != nil {
		client = fmt.Sprintf("%s(%s)", s.conn.RemoteAddr().String(), s.user.Name)
	} else {
		client = s.conn.RemoteAddr().String()
	}

	var err error
	if s.request.command == 0x01 {
		// CONNECT
		var remoteAddr string
		if s.request.useHostname {
			remoteAddr = fmt.Sprintf("%s:%d", s.request.hostname, s.request.port)
		} else {
			remoteAddr = fmt.Sprintf("[%s]:%d", s.request.ip.String(), s.request.port)
		}

		log.Infof("%s connecting to %s", client, remoteAddr)

		var remote net.Conn
		if s.request.useHostname {
			if remote, err = connectHostname(s.server, s.user, s.request.hostname, s.request.port); err != nil {
				s.conn.Write(s.request.Answer(0x04))
				return err
			}
		} else {
			if remote, err = connectIP(s.server, s.user, s.request.ip, s.request.port); err != nil {
				s.conn.Write(s.request.Answer(0x04))
				return err
			}
		}

		s.conn.Write(s.request.Answer(0x00))

		go proxyChannel(s.config, s.conn, remote)
		proxyChannel(s.config, remote, s.conn)

		return nil
	} else if s.request.command == 0x02 {
		// TCP BIND
		port, err := s.server.GetTCPPort()
		if err != nil {
			s.conn.Write(s.request.Answer(0x01))
			return err
		}
		defer s.server.FreeTCPPort(port)

		var listener net.Listener
		if s.config.Server.TCPBindAddrIsHostname {
			listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", s.config.Server.TCPBindAddrHostname, port))
		} else {
			listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", s.config.Server.TCPBindAddrIP.String(), port))
		}
		if err != nil {
			s.conn.Write(s.request.Answer(0x01))
			return err
		}
		defer listener.Close()

		tcpListener := listener.(*net.TCPListener)
		tcpListener.SetDeadline(time.Now().Add(time.Duration(s.config.Server.Timeout) * time.Second))

		if s.config.Server.TCPBindAddrIsHostname {
			log.Infof("%s request tcp bind on %s:%d", client, s.config.Server.TCPBindAddrHostname, port)
			s.conn.Write(s.request.AnswerBindHostname(0x05, 0x00, s.config.Server.TCPBindAddrHostname, uint16(port)))
		} else {
			log.Infof("%s request tcp bind on [%s]:%d", client, s.config.Server.TCPBindAddrIP.String(), port)
			s.conn.Write(s.request.AnswerBindIP(0x05, 0x00, s.config.Server.TCPBindAddrIP, uint16(port)))
		}

		remote, err := listener.Accept()
		if err != nil {
			s.conn.Write(s.request.AnswerBindIP(0x05, 0x06, s.config.Server.TCPBindAddrIP, uint16(port)))
			return err
		}
		defer remote.Close()

		remoteAddr := remote.RemoteAddr().(*net.TCPAddr)
		log.Infof("%s get new tcp connection from %s", s.conn.RemoteAddr().String(), remote.RemoteAddr().String())
		s.conn.Write(s.request.AnswerBindIP(0x05, 0x00, remoteAddr.IP, uint16(remoteAddr.Port)))

		go proxyChannel(s.config, s.conn, remote)
		proxyChannel(s.config, remote, s.conn)

		return nil
	} else if s.request.command == 0x03 {
		// UDP ASSOCIATION
		port, err := s.server.GetUDPPort()
		if err != nil {
			s.conn.Write(s.request.Answer(0x01))
			return err
		}
		defer s.server.FreeUDPPort(port)

		var listener net.PacketConn
		if s.config.Server.TCPBindAddrIsHostname {
			listener, err = net.ListenPacket("udp", fmt.Sprintf("%s:%d", s.config.Server.UDPAssociationAddrHostname, port))
		} else {
			listener, err = net.ListenPacket("udp", fmt.Sprintf("%s:%d", s.config.Server.UDPAssociationAddrIP.String(), port))
		}
		if err != nil {
			s.conn.Write(s.request.Answer(0x01))
			return err
		}
		defer listener.Close()

		if s.config.Server.TCPBindAddrIsHostname {
			log.Infof("%s request udp association to %s:%d", client, s.config.Server.UDPAssociationAddrHostname, port)
			s.conn.Write(s.request.AnswerBindHostname(0x05, 0x00, s.config.Server.UDPAssociationAddrHostname, uint16(port)))
		} else {
			log.Infof("%s request udp association to [%s]:%d", client, s.config.Server.UDPAssociationAddrIP.String(), port)
			s.conn.Write(s.request.AnswerBindIP(0x05, 0x00, s.config.Server.UDPAssociationAddrIP, uint16(port)))
		}

		go udpAssociate(s.config, listener)

		ignore := make([]byte, 32)
		for {
			_, err = s.conn.Read(ignore)
			if err != nil {
				return nil
			}
		}
	}

	return fmt.Errorf("socks5 client send unknown command and somehow it was validated")
}
