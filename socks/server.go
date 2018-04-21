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
	"crypto/tls"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/swork9/virgild/models"
)

type Server struct {
	listener net.Listener
	tls      bool
	work     bool

	config      *models.Config
	authMethods []models.AuthMethod
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

	if s.tls {
		log.Infof("Starting new tls socks server. Configuration:\n"+
			"Bind:\t\t\t\t%s\n"+
			"Auth methods:\t\t\t%s\n"+
			"TCP bind allowed:\t\t%t\n"+
			"UDP association allowed:\t%t\n",
			s.config.Server.Bind, authMethods, s.config.Server.AllowTCPBind, s.config.Server.AllowUDPAssociation)
	} else {
		log.Infof("Starting new socks server. Configuration:\n"+
			"Bind:\t\t\t\t%s\n"+
			"Auth methods:\t\t\t%s\n"+
			"TCP bind allowed:\t\t%t\n"+
			"UDP association allowed:\t%t\n",
			s.config.Server.Bind, authMethods, s.config.Server.AllowTCPBind, s.config.Server.AllowUDPAssociation)
	}

	for s.work {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.work {
				log.Errorln("(socks server)", err)
			}
			continue
		}

		go handle(s, conn)
	}

	return nil
}

func NewServer(config *models.Config, authMethods []models.AuthMethod) (*Server, error) {
	server := &Server{tls: false, work: true, config: config, authMethods: authMethods}

	return server, nil
}

func NewTLSServer(config *models.Config, authMethods []models.AuthMethod) (*Server, error) {
	server := &Server{tls: true, work: true, config: config, authMethods: authMethods}

	return server, nil
}
