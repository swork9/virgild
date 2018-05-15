# virgild
Easy to use socks(4/4a/5) server.

### Current state
   - Full support for socks connection command.
   - Experimental support for tcp bind.
   - Experimental support for udp association.
   - User authentication via plain text db.
   - User authentication via sql (odbc too).
   - TLS server.

### TODO
   - Web panel for monitoring.
   - Bugs free code.

### Installation

##### From sources
To compile virgild from sources, you'll need golang (https://golang.org/).
```
git clone https://github.com/swork9/virgild
cd virgild
go get -d ./...
go build -v -tags db_mysql db_odbc db_sqlite db_postgresql
```

##### Updating
```
go get -u github.com/swork9/virgild
```

### Usage

```
Usage of ./virgild:
  -c string
        Config file to use (default "virgild.conf")
  -d    Daemonize service and detach from tty
```

In most cases, you will want to run virgild as a daemon, like:

```
./virgild -d -c /etc/virgild.conf
```

### Authentication methods

##### Plain text

To configure authentication from plain text file, first change the next section of the configuration file:
```
[AuthPlainText]
path = plain.db
hashMethod = md5 # sha256, sha512
```

Next, create a text file in the following format:
```
key0:value0
key1:value1
key2:value2
```

Where the key is the username, and the value is its password, hashed by the method you selected in the configuration.

##### SQL
To configure authentication from sql db, first change the next section of the configuration file:
```
[AuthSQL]
DBType = mysql
DBConnection = "user:password@tcp(127.0.0.1:3306)/hello"
DBMaxConnections = 8
```

Next, make sure, that you have table in your db with at least two keys: first for username, second for password.
You can use next mysql query to create table:
```
CREATE TABLE users (username VARCHAR(256) NOT NULL, password VARCHAR(256) NOT NULL, PRIMARY KEY (username));
```

Check you config file to make sure, that you have working SELECT query to get user:
```
querySelectUser = "SELECT password FROM users WHERE username=? LIMIT 1;"
```
This query must return only one value containing the hashed password.

### Another
Feel free to open issues and/or submit pull requests, but please wait until I close todo and finish what I want.
Thanks!
