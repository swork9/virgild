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

package models

import "net"

type SubnetChecker struct {
	subnets []*net.IPNet
}

func (s *SubnetChecker) Empty() bool {
	return len(s.subnets) == 0
}

func (s *SubnetChecker) Load(subnets []string) error {
	s.subnets = []*net.IPNet{}
	for _, subnet := range subnets {
		_, i, err := net.ParseCIDR(subnet)
		if err != nil {
			return err
		}

		s.subnets = append(s.subnets, i)
	}

	return nil
}

func (s *SubnetChecker) Contains(ip net.IP) (*net.IPNet, bool) {
	for _, subnet := range s.subnets {
		if subnet.Contains(ip) {
			return subnet, true
		}
	}

	return nil, false
}
