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
	"fmt"
	"net"

	"virgild/models"
)

func checkSubnetsRules(s *Server, user *models.User, conn net.Conn) error {
	if s.allowedSubnets.Empty() && s.blockedSubnets.Empty() {
		return nil
	}
	if s.config.Subnets.UserWillIgnore && user != nil {
		return nil
	}

	ip := conn.RemoteAddr().(*net.TCPAddr).IP
	if !s.allowedSubnets.Empty() {
		if _, contains := s.allowedSubnets.Contains(ip); !contains {
			return fmt.Errorf("blocked, not from allowed subnets")
		}
	}

	if !s.blockedSubnets.Empty() {
		if subnet, contains := s.blockedSubnets.Contains(ip); contains {
			return fmt.Errorf("blocked, from restricted subnet %s", subnet.String())
		}
	}

	return nil
}

func checkRemoteSubnetsRules(s *Server, user *models.User, ip net.IP) error {
	if s.config.Subnets.UserWillIgnore && user != nil {
		return nil
	}

	if !s.allowedRemoteSubnets.Empty() {
		if _, contains := s.allowedRemoteSubnets.Contains(ip); !contains {
			return fmt.Errorf("blocked remote addr %s, not from allowed remote subnets", ip.String())
		}
	}

	return nil
}
