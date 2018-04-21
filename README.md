# virgild
Easy to use socks(4/4a/5) server.

### Current state
   - Full support for socks connection command.
   - User authorization via plain text db.
   - TLS server.

### TODO
   - Add support for tcp bind and udp association.
   - sql/odbc user authentication.
   - Web panel for monitoring.
   - Bugs free code.

### Installation

##### From sources
To compile virgild from sources, you'll need golang (https://golang.org/).
```
git clone https://github.com/swork9/virgild
cd virgild
go get -d ./...
go build
```

### Usage

```
Usage of ./virgild:
  -c string
        Config file to use (default "virgild.conf")
  -d    Daemonize service and starts it as another user based on config
```

In most cases, you will want to run virgild as a daemon, like:

```
./virgild -d -c /etc/virgild.conf
```

### Authentication methods

##### Plain text

To configure authorization from plain text file, first change the next section of the configuration file:
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

### Another
Feel free to open issues and/or submit pull requests, but please wait until I close todo and finish what I want.
Thanks!
