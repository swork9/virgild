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
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/swork9/virgild/models"
)

func udpSendSocksPacket(listener net.PacketConn, from *net.UDPAddr, data []byte) error {
	headerLen := 4
	dataLen := len(data)
	if dataLen < headerLen {
		return fmt.Errorf("socks5 udp packet header length < %d", headerLen)
	}

	if data[0] != 0x00 || data[1] != 0x00 {
		return fmt.Errorf("socks5 udp packet header RSV not null")
	}
	if data[2] != 0x00 {
		return fmt.Errorf("socks5 udp packet fragmentation not supported, packet dropped")
	}

	var ip net.IP
	var hostname string

	if data[3] == 0x01 {
		headerLen += 4
		if dataLen < headerLen {
			return fmt.Errorf("socks5 udp packet header length < %d", headerLen)
		}

		ip = data[4:8]
	} else if data[3] == 0x02 {
		headerLen++
		if dataLen < headerLen {
			return fmt.Errorf("socks5 udp packet header length < %d", headerLen)
		}
		headerLen += int(data[4])
		if dataLen < headerLen {
			return fmt.Errorf("socks5 udp packet header length < %d", headerLen)
		}

		hostname = string(data[5:int(data[4])])
	} else if data[3] == 0x03 {
		headerLen += 16
		if dataLen < headerLen {
			return fmt.Errorf("socks5 udp packet header length < %d", headerLen)
		}

		ip = data[4:20]
	} else {
		return fmt.Errorf("socks5 udp packet header unknown address type")
	}

	headerLen += 2
	if dataLen < headerLen {
		return fmt.Errorf("socks5 udp packet header length < %d", headerLen)
	}

	port := binary.BigEndian.Uint16(data[headerLen-2 : headerLen])

	if len(hostname) > 0 {
		ips, err := net.LookupIP(hostname)
		if err != nil {
			return err
		}

		for _, ip := range ips {
			to := &net.UDPAddr{IP: ip, Port: int(port)}

			_, err = listener.WriteTo(data[headerLen:], to)
			if err == nil {
				log.Debugf("%s sending udp to %s", from.String(), to.String())
				return nil
			}

			return fmt.Errorf("udp lookup failed: destination host unreachable")
		}
	} else {
		to := &net.UDPAddr{IP: ip, Port: int(port)}
		log.Debugf("%s sending udp to %s", from.String(), to.String())

		listener.WriteTo(data[headerLen:], to)
	}

	return nil
}

func udpRelayPacket(listener net.PacketConn, from *net.UDPAddr, to *net.UDPAddr, data []byte) error {
	var buffer bytes.Buffer

	// RSV
	buffer.WriteByte(0x00)
	buffer.WriteByte(0x00)

	// FRAG
	buffer.WriteByte(0x00)

	if len(from.IP) == 4 {
		buffer.WriteByte(0x01)
		binary.Write(&buffer, binary.LittleEndian, from.IP)
	} else if len(from.IP) == 16 {
		buffer.WriteByte(0x03)
		binary.Write(&buffer, binary.LittleEndian, from.IP)
	} else {
		return fmt.Errorf("socks5 udp packet has unknown address type")
	}

	binary.Write(&buffer, binary.BigEndian, uint16(from.Port))

	// DATA
	binary.Write(&buffer, binary.LittleEndian, data)

	log.Debugf("%s relaying udp to %s", from.String(), to.String())

	listener.WriteTo(buffer.Bytes(), to)

	return nil
}

func udpAssociate(config *models.Config, listener net.PacketConn) error {
	var ret int
	var addr net.Addr
	var client, remote *net.UDPAddr
	var err error

	// I want to make sure, that we don't have fragmentation in udp.
	buffer := make([]byte, 65535)

	timeoutDuration := time.Duration(config.Server.Timeout) * time.Second

	for {
		listener.SetReadDeadline(time.Now().Add(timeoutDuration))

		ret, addr, err = listener.ReadFrom(buffer)
		if err != nil {
			return err
		}
		remote = addr.(*net.UDPAddr)

		if client == nil {
			client = remote
		}

		if bytes.Equal(client.IP, remote.IP) && client.Port == remote.Port {
			err = udpSendSocksPacket(listener, client, buffer[0:ret])
		} else {
			err = udpRelayPacket(listener, remote, client, buffer[0:ret])
		}

		if err != nil {
			log.Debugf("(udp association)", err)
		}
	}
}
