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

import (
	"net"

	"github.com/swork9/virgild/auth"
)

type Config struct {
	Server        ServerConfig
	AuthSQL       AuthSQLConfig
	AuthPlainText AuthPlainTextConfig
	Subnets       SubnetsConfig
}

type ServerConfig struct {
	UID string
	GID string

	Bind    string
	Timeout int
	Buffer  int

	PrivateKey string
	PublicKey  string

	AllowAnonymous   bool
	AllowHTTPConnect bool

	AllowTCPBind      bool
	TCPBindAddr       string
	TCPBindPortsStart int
	TCPBindPortsEnd   int

	// Don't use it in your config file, please, it's for internal use.
	TCPBindAddrIsHostname bool
	TCPBindAddrIP         net.IP
	TCPBindAddrHostname   string

	AllowUDPAssociation      bool
	UDPAssociationAddr       string
	UDPAssociationPortsStart int
	UDPAssociationPortsEnd   int

	// Don't use it in your config file, please, it's for internal use.
	UDPAssociationAddrIsHostname bool
	UDPAssociationAddrIP         net.IP
	UDPAssociationAddrHostname   string

	LogLevel string
	LogFile  string
}

type AuthSQLConfig struct {
	DBType           string
	DBConnection     string
	DBMaxConnections int

	HashMethod   string
	CacheTimeout int64

	QuerySelectUser string
}

type AuthPlainTextConfig struct {
	Path       string
	HashMethod string
}

type SubnetsConfig struct {
	UserWillIgnore bool

	Allow []string
	Deny  []string
}

func (c *Config) GetAuthMethods() ([]AuthMethod, error) {
	authMethods := []AuthMethod{}
	if len(c.AuthPlainText.Path) > 0 {
		authPlain, err := auth.NewAuthPlain(c.AuthPlainText.Path, c.AuthPlainText.HashMethod)
		if err != nil {
			return nil, err
		}
		if err = authPlain.Init(); err != nil {
			return nil, err
		}

		authMethods = append(authMethods, authPlain)
	}
	if len(c.AuthSQL.DBType) > 0 {
		authSQL, err := auth.NewAuthSQL(
			c.AuthSQL.DBType,
			c.AuthSQL.DBConnection,
			c.AuthSQL.DBMaxConnections,

			c.AuthSQL.HashMethod,
			c.AuthSQL.CacheTimeout,

			c.AuthSQL.QuerySelectUser,
		)
		if err != nil {
			return nil, err
		}
		if err = authSQL.Init(); err != nil {
			return nil, err
		}

		authMethods = append(authMethods, authSQL)
	}

	return authMethods, nil
}
