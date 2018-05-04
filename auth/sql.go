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

package auth

import (
	"database/sql"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	// Uncomment next line, if you need ODBC driver
	//_ "github.com/alexbrainman/odbc"
)

type cachedUser struct {
	hashedPassword string
	stored         int64
}

type AuthSQL struct {
	dbType string
	db     *sql.DB

	hasher            *authHasher
	users             map[string]*cachedUser
	usersMutex        *sync.RWMutex
	usersCacheTimeout int64

	querySelectUser string
}

func (a *AuthSQL) GetUserFromCache(username string) (string, bool) {
	if a.usersCacheTimeout < 0 {
		return "", false
	}

	a.usersMutex.RLock()
	user, ok := a.users[username]
	a.usersMutex.RUnlock()
	if !ok {
		return "", false
	}

	if a.usersCacheTimeout > 0 {
		if time.Now().Unix()-user.stored > a.usersCacheTimeout {
			a.usersMutex.Lock()
			delete(a.users, username)
			a.usersMutex.Unlock()
			return "", false
		}
		return user.hashedPassword, true
	} else if a.usersCacheTimeout == 0 {
		return user.hashedPassword, true
	} else {
		return "", false
	}
}

func (a *AuthSQL) PutUserToCache(username, hashedPassword string) {
	if a.usersCacheTimeout >= 0 {
		a.usersMutex.Lock()
		a.users[username] = &cachedUser{
			hashedPassword: hashedPassword,
			stored:         time.Now().Unix(),
		}
		a.usersMutex.Unlock()
	}
}

func (a *AuthSQL) GetName() string {
	return a.dbType
}

func (a *AuthSQL) Init() error {
	var err error
	if err = a.db.Ping(); err != nil {
		return err
	}

	return nil
}

func (a *AuthSQL) Close() error {
	if a.db != nil {
		a.db.Close()
	}

	return nil
}

func (a *AuthSQL) Check(username, password string) (bool, error) {
	hashedPassword, ok := a.GetUserFromCache(username)
	if !ok {
		stmt, err := a.db.Prepare(a.querySelectUser)
		if err != nil {
			return false, err
		}
		defer stmt.Close()

		// Well, I know about SQL injections, but AS FAR AS I KNOW, prepared stmt will help in most sql drivers.
		rows, err := stmt.Query(username)
		if err != nil {
			return false, err
		}
		defer rows.Close()

		for rows.Next() {
			err = rows.Scan(&hashedPassword)
			if err != nil {
				return false, err
			}
		}
	}

	if hashedPassword == a.hasher.Hash(password) {
		if !ok {
			a.PutUserToCache(username, hashedPassword)
		}

		return true, nil
	}

	return false, nil
}

func NewAuthSQL(dbType, dbConnection string, dbMaxConnections int, hashMethod string, cacheTimeout int64, querySelectUser string) (*AuthSQL, error) {
	hasher, err := newHasher(hashMethod)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(dbType, dbConnection)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(dbMaxConnections)

	auth := &AuthSQL{
		dbType: dbType,
		db:     db,

		hasher:            hasher,
		users:             map[string]*cachedUser{},
		usersMutex:        &sync.RWMutex{},
		usersCacheTimeout: cacheTimeout,

		querySelectUser: querySelectUser,
	}

	return auth, nil
}
