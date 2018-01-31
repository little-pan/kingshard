// Copyright 2016 The kingshard Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/flike/kingshard/backend"
	"github.com/flike/kingshard/core/golog"
	"github.com/flike/kingshard/core/hack"
	"github.com/flike/kingshard/mysql"
	"time"
)

const (
	moduleConn = "server.ClientConn"
)

//client <-> proxy
type ClientConn struct {
	sync.Mutex

	pkg *mysql.PacketIO

	c net.Conn

	proxy *Server

	capability uint32

	connectionId uint32

	status    uint16
	collation mysql.CollationId
	charset   string

	user string
	db   string

	salt []byte

	schema *Schema

	txConns map[*backend.Node]*backend.BackendConn

	closed bool

	lastInsertId int64
	affectedRows int64

	stmtId uint32

	stmts map[uint32]*Stmt //prepare相关,client端到proxy的stmt
}

var DEFAULT_CAPABILITY uint32 = mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_LONG_FLAG |
	mysql.CLIENT_CONNECT_WITH_DB | mysql.CLIENT_PROTOCOL_41 |
	mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_SECURE_CONNECTION

var baseConnId uint32 = 10000

func (c *ClientConn) ThreadId() uint32 {
	return c.connectionId
}

func (c *ClientConn) IsAllowConnect() bool {
	clientHost, _, err := net.SplitHostPort(c.c.RemoteAddr().String())
	if err != nil {
		fmt.Println(err)
	}
	clientIP := net.ParseIP(clientHost)

	ipVec := c.proxy.allowips[c.proxy.allowipsIndex]
	if ipVecLen := len(ipVec); ipVecLen == 0 {
		return true
	}
	for _, ip := range ipVec {
		if ip.Equal(clientIP) {
			return true
		}
	}

	golog.Warn(moduleConn, "IsAllowConnect", "Access denied by kindshard", 0,
		"ip address", c.c.RemoteAddr().String(),
		"error code", mysql.ER_ACCESS_DENIED_ERROR)
	return false
}

func (c *ClientConn) Handshake() error {
	if err := c.writeInitialHandshake(); err != nil {
		golog.Error(moduleConn, "Handshake", err.Error(), c.connectionId)
		return err
	}

	if err := c.readHandshakeResponse(); err != nil {
		golog.Error(moduleConn, "Handshake", err.Error(), c.connectionId)
		return err
	}

	if err := c.writeOK(nil); err != nil {
		golog.Error(moduleConn, "Handshake",  err.Error(), c.connectionId)
		return err
	}

	c.pkg.Sequence = 0
	return nil
}

func (c *ClientConn) Close() error {
	if c.closed {
		return nil
	}

	c.c.Close()
	c.closed = true

	return nil
}

func (c *ClientConn) writeInitialHandshake() error {
	data := make([]byte, 4, 128)

	//min version 10
	data = append(data, 10)

	//server version[00]
	data = append(data, mysql.ServerVersion...)
	data = append(data, 0)

	//connection id
	data = append(data, byte(c.connectionId), byte(c.connectionId>>8), byte(c.connectionId>>16), byte(c.connectionId>>24))

	//auth-plugin-data-part-1
	data = append(data, c.salt[0:8]...)

	//filter [00]
	data = append(data, 0)

	//capability flag lower 2 bytes, using default capability here
	data = append(data, byte(DEFAULT_CAPABILITY), byte(DEFAULT_CAPABILITY>>8))

	//charset, utf-8 default
	data = append(data, uint8(mysql.DEFAULT_COLLATION_ID))

	//status
	data = append(data, byte(c.status), byte(c.status>>8))

	//below 13 byte may not be used
	//capability flag upper 2 bytes, using default capability here
	data = append(data, byte(DEFAULT_CAPABILITY>>16), byte(DEFAULT_CAPABILITY>>24))

	//filter [0x15], for wireshark dump, value is 0x15
	data = append(data, 0x15)

	//reserved 10 [00]
	data = append(data, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

	//auth-plugin-data-part-2
	data = append(data, c.salt[8:]...)

	//filter [00]
	data = append(data, 0)

	return c.writePacket(data)
}

func (c *ClientConn) readPacket() ([]byte, error) {
	return c.pkg.ReadPacket()
}

func (c *ClientConn) writePacket(data []byte) error {
	return c.pkg.WritePacket(data)
}

func (c *ClientConn) writePacketBatch(total, data []byte, direct bool) ([]byte, error) {
	return c.pkg.WritePacketBatch(total, data, direct)
}

func (c *ClientConn) readHandshakeResponse() error {
	data, err := c.readPacket()

	if err != nil {
		return err
	}

	pos := 0

	//capability
	c.capability = binary.LittleEndian.Uint32(data[:4])
	pos += 4

	//skip max packet size
	pos += 4

	//charset, skip, if you want to use another charset, use set names
	// ---------------------------------------------------------------------
	// Default client charset as mysql client
	// @since 2018-01-25 little-pan
	collation := mysql.CollationId(data[pos])
	charset, err := mysql.Charset(collation)
	if err != nil {
		return mysql.NewDefaultError(mysql.ER_UNKNOWN_COLLATION, err)
	}
	c.charset  = charset
	c.collation= collation
	pos++

	//skip reserved 23[00]
	pos += 23

	//user name
	c.user = string(data[pos : pos+bytes.IndexByte(data[pos:], 0)])

	pos += len(c.user) + 1

	//auth length and auth
	authLen := int(data[pos])
	pos++
	auth := data[pos : pos+authLen]

	checkAuth := mysql.CalcPassword(c.salt, []byte(c.proxy.cfg.Password))
	if c.user != c.proxy.cfg.User || !bytes.Equal(auth, checkAuth) {
		// Error() changed to Debug(): only need in dev mode
		// @since 2018-01-18 little-pan
		golog.Debug(moduleConn, "readHandshakeResponse", "auth error", c.connectionId,
			"auth", auth,
			"checkAuth", checkAuth,
			"client_user", c.user,
			"config_set_user", c.proxy.cfg.User,
			// `passworld` changed to `config_set_password`
			"config_set_password", c.proxy.cfg.Password)
		// trim port field in user information
		// @since 2018-01-18 little-pan
		raddr := c.c.RemoteAddr().String()
		rhost, _, err := net.SplitHostPort(raddr)
		if err != nil {
			rhost = raddr
		}
		return mysql.NewDefaultError(mysql.ER_ACCESS_DENIED_ERROR, c.user, rhost, "YES")
	}

	pos += authLen

	var db string
	if c.capability&mysql.CLIENT_CONNECT_WITH_DB > 0 {
		if len(data[pos:]) == 0 {
			return nil
		}

		db = string(data[pos : pos+bytes.IndexByte(data[pos:], 0)])
		pos += len(c.db) + 1

	} else {
		//if connect without database, use default db
		db = c.proxy.schema.db
	}
	c.db = db

	return nil
}

func (c *ClientConn) Run() {
	defer func() {
		r := recover()
		if err, ok := r.(error); ok {
			const size = 4096
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]

			golog.Error(moduleConn, "Run", err.Error(), c.connectionId, 
				                                    "stack", string(buf))
		}

		c.Close()
	}()
	// server loop
	for {
		data, err := c.readPacket()

		if err != nil {
			// log read-packet error
			// @since 2018-01-31 little-pan
			if err != mysql.ErrBadConn {
				golog.Error(moduleConn, "Run", err.Error(), c.connectionId)
			}
			return
		}

		if err := c.dispatch(data); err != nil {
			c.proxy.counter.IncrErrLogTotal()
			golog.Error(moduleConn, "Run", err.Error(), c.connectionId)
			c.writeError(err)
			if err == mysql.ErrBadConn {
				return
			}
		}

		c.pkg.Sequence = 0
	}
}

func (c *ClientConn) dispatch(data []byte) error {
	// statistics
	counter := c.proxy.counter
	counter.IncrClientQPS()
	counter.IncrQuestions()
	// do-dispatch
	cmd := data[0]
	data = data[1:]
	switch cmd {
	case mysql.COM_QUIT:
		c.handleRollback()
		c.Close()
		return nil
	case mysql.COM_QUERY:
		// charset transfer, eg. gbk to utf8 etc
		// @since 2018-01-24 little-pan
		query := mysql.Decode(data, c.charset)
		return c.handleQuery(query)
	case mysql.COM_PING:
		return c.writeOK(nil)
	case mysql.COM_INIT_DB:
		return c.handleUseDB(hack.String(data))
	case mysql.COM_FIELD_LIST:
		return c.handleFieldList(data)
	case mysql.COM_STMT_PREPARE:
		return c.handleStmtPrepare(hack.String(data))
	case mysql.COM_STMT_EXECUTE:
		return c.handleStmtExecute(data)
	case mysql.COM_STMT_CLOSE:
		return c.handleStmtClose(data)
	case mysql.COM_STMT_SEND_LONG_DATA:
		return c.handleStmtSendLongData(data)
	case mysql.COM_STMT_RESET:
		return c.handleStmtReset(data)
	case mysql.COM_SET_OPTION:
		return c.writeEOF(0)
	// add feature-com-stat since 2018-01-31 little-pan
	case mysql.COM_STATISTICS:
		return c.handleStatistics()
	default:
		msg := fmt.Sprintf("command %d not supported now", cmd)
		golog.Error(moduleConn, "dispatch", msg, c.connectionId)
		return mysql.NewError(mysql.ER_UNKNOWN_ERROR, msg)
	}

	return nil
}

func (c *ClientConn) handleStatistics() error {
	// Statistics information format -
	//Uptime: SECONDS Threads: 1  Questions: 985  Slow queries: 0  Opens: 83  Flush tables: 1  Open tables: 76
	//Queries per second avg: 0.084
	s := c.proxy
	// Uptime
	utm := s.counter.CalcUptime()
	seconds := utm / time.Second
	// Counter
	cnt := s.counter
	threads   := cnt.ClientConns
	questions := cnt.Questions
	slows     := cnt.OldSlowLogTotal
	qps       := cnt.OldClientQPS
	// write
	result := fmt.Sprintf("Uptime:  %d  Threads: %d  Questions: %d  Slow queries: %d  Opens: 0  Flush tables: 0  " +
		"Open tables: 0  Queries per second avg: %d", seconds, threads, questions, slows, qps)
	data := make([]byte, 4, 4 + len(result))
	data = append(data, hack.Slice(result)...)
	c.writePacket(data)
	return nil
}

func (c *ClientConn) writeOK(r *mysql.Result) error {
	if r == nil {
		r = &mysql.Result{Status: c.status}
	}
	data := make([]byte, 4, 32)

	data = append(data, mysql.OK_HEADER)

	data = append(data, mysql.PutLengthEncodedInt(r.AffectedRows)...)
	data = append(data, mysql.PutLengthEncodedInt(r.InsertId)...)

	if c.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		data = append(data, byte(r.Status), byte(r.Status>>8))
		data = append(data, 0, 0)
	}

	return c.writePacket(data)
}

func (c *ClientConn) writeError(e error) error {
	var m *mysql.SqlError
	var ok bool
	if m, ok = e.(*mysql.SqlError); !ok {
		m = mysql.NewError(mysql.ER_UNKNOWN_ERROR, e.Error())
	}

	data := make([]byte, 4, 16+len(m.Message))

	data = append(data, mysql.ERR_HEADER)
	data = append(data, byte(m.Code), byte(m.Code>>8))

	if c.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		data = append(data, '#')
		data = append(data, m.State...)
	}

	data = append(data, m.Message...)

	return c.writePacket(data)
}

func (c *ClientConn) writeEOF(status uint16) error {
	data := make([]byte, 4, 9)

	data = append(data, mysql.EOF_HEADER)
	if c.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		data = append(data, 0, 0)
		data = append(data, byte(status), byte(status>>8))
	}

	return c.writePacket(data)
}

func (c *ClientConn) writeEOFBatch(total []byte, status uint16, direct bool) ([]byte, error) {
	data := make([]byte, 4, 9)

	data = append(data, mysql.EOF_HEADER)
	if c.capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		data = append(data, 0, 0)
		data = append(data, byte(status), byte(status>>8))
	}

	return c.writePacketBatch(total, data, direct)
}
