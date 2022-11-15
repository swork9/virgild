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
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"virgild/models"
)

type Server struct {
	listener net.Listener
	tls      bool
	work     bool

	tcpPorts      map[int]bool
	tcpPortsMutex *sync.Mutex
	udpPorts      map[int]bool
	udpPortsMutex *sync.Mutex

	config      *models.Config
	authMethods []models.AuthMethod

	allowedSubnets       *models.SubnetChecker
	blockedSubnets       *models.SubnetChecker
	allowedRemoteSubnets *models.SubnetChecker
}

func (s *Server) Init() error {
	if s.tls {
		keypair, err := tls.LoadX509KeyPair(s.config.Server.PublicKey, s.config.Server.PrivateKey)
		if err != nil {
			return err
		}

		tlsConfig := &tls.Config{Certificates: []tls.Certificate{keypair}, MinVersion: tls.VersionTLS12}
		s.listener, err = tls.Listen("tcp", s.config.Server.Bind, tlsConfig)
		if err != nil {
			return err
		}
	} else {
		var err error
		s.listener, err = net.Listen("tcp", s.config.Server.Bind)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) Close() error {
	s.work = false

	if s.listener != nil {
		err := s.listener.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) Start() error {
	var authMethods string
	if s.config.Server.AllowAnonymous {
		authMethods += "anonymous "
	}
	for _, authMethod := range s.authMethods {
		authMethods += authMethod.GetName() + " "
	}

	log.Infof("Starting new proxy server. Configuration:\n"+
		"Bind:\t\t\t\t%s\n"+
		"TLS:\t\t\t\t%t\n"+
		"Auth methods:\t\t\t%s\n"+
		"HTTP allowed:\t\t%t\n"+
		"TCP bind allowed:\t\t%t\n"+
		"UDP association allowed:\t%t\n"+
		"Filter by allowed subnets:\t%t\n"+
		"Filter by blocked subnets:\t%t\n"+
		"Filter by remote subnets:\t%t\n",
		s.config.Server.Bind,
		s.tls,
		authMethods,
		s.config.Server.AllowHTTP,
		s.config.Server.AllowTCPBind,
		s.config.Server.AllowUDPAssociation,
		!s.allowedSubnets.Empty(),
		!s.blockedSubnets.Empty(),
		!s.allowedRemoteSubnets.Empty())

	for s.work {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.work {
				log.Errorln("(proxy server)", err)
			}
			continue
		}

		go handle(s, conn)
	}

	return nil
}

func (s *Server) GetTCPPort() (int, error) {
	s.tcpPortsMutex.Lock()
	defer s.tcpPortsMutex.Unlock()

	for i := s.config.Server.TCPBindPortsStart; i <= s.config.Server.TCPBindPortsEnd; i++ {
		used := s.tcpPorts[i]
		if !used {
			s.tcpPorts[i] = true
			return i, nil
		}
	}

	return 0, fmt.Errorf("can't assign new tcp port for bind: all ports already in use")
}

func (s *Server) FreeTCPPort(port int) {
	s.tcpPortsMutex.Lock()
	defer s.tcpPortsMutex.Unlock()

	s.tcpPorts[port] = false
}

func (s *Server) GetUDPPort() (int, error) {
	s.udpPortsMutex.Lock()
	defer s.udpPortsMutex.Unlock()

	for i := s.config.Server.UDPAssociationPortsStart; i <= s.config.Server.UDPAssociationPortsEnd; i++ {
		used := s.udpPorts[i]
		if !used {
			s.udpPorts[i] = true
			return i, nil
		}
	}

	return 0, fmt.Errorf("can't assign new udp port for bind: all ports already in use")
}

func (s *Server) FreeUDPPort(port int) {
	s.udpPortsMutex.Lock()
	defer s.udpPortsMutex.Unlock()

	s.udpPorts[port] = false
}

func NewServer(config *models.Config,
	tls bool,
	authMethods []models.AuthMethod,
	allowedSubnets *models.SubnetChecker,
	blockedSubnets *models.SubnetChecker,
	allowedRemoteSubnets *models.SubnetChecker) (*Server, error) {

	server := &Server{
		tls:  tls,
		work: true,

		tcpPorts:      map[int]bool{},
		tcpPortsMutex: &sync.Mutex{},
		udpPorts:      map[int]bool{},
		udpPortsMutex: &sync.Mutex{},

		config:      config,
		authMethods: authMethods,

		allowedSubnets:       allowedSubnets,
		blockedSubnets:       blockedSubnets,
		allowedRemoteSubnets: allowedRemoteSubnets,
	}

	return server, nil
}
