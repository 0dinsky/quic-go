package handshake

import (
	"context"
	"crypto/tls"
	"reflect"
	"unsafe"

	utls "github.com/metacubex/utls"
)

// quicTLSConn — интерфейс для *tls.QUICConn и *utlsQUICConn
type quicTLSConn interface {
	Start(ctx context.Context) error
	Close() error
	NextEvent() tls.QUICEvent
	HandleData(level tls.QUICEncryptionLevel, data []byte) error
	SetTransportParameters(params []byte)
	ConnectionState() tls.ConnectionState
	SendSessionTicket(opts tls.QUICSessionTicketOptions) error
	StoreSession(session *tls.SessionState) error
}

// stdQUICConn оборачивает *tls.QUICConn в интерфейс quicTLSConn
type stdQUICConn struct{ *tls.QUICConn }

func (c *stdQUICConn) StoreSession(session *tls.SessionState) error {
	return c.QUICConn.StoreSession(session)
}

// utlsQUICConn оборачивает *utls.UQUICConn в интерфейс quicTLSConn.
// Патчит client_random перед запуском handshake.
type utlsQUICConn struct {
	conn               *utls.UQUICConn
	uconn              *utls.UConn // доступ через reflection
	clientRandomPrefix []byte
	clientRandomMask   []byte
}

func newUTLSQUICConn(tlsConf *tls.Config, id utls.ClientHelloID, prefix, mask []byte) *utlsQUICConn {
	cfg := &utls.QUICConfig{
		TLSConfig: &utls.Config{
			ServerName:             tlsConf.ServerName,
			RootCAs:                tlsConf.RootCAs,
			NextProtos:             tlsConf.NextProtos,
			InsecureSkipVerify:     tlsConf.InsecureSkipVerify,
			MinVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: tlsConf.SessionTicketsDisabled,
		},
		EnableSessionEvents: true,
	}
	q := utls.UQUICClient(cfg, id)

	// Получаем приватное поле conn *UConn через reflection
	var uconn *utls.UConn
	v := reflect.ValueOf(q).Elem()
	f := v.FieldByName("conn")
	if f.IsValid() {
		uconn = (*utls.UConn)(unsafe.Pointer(f.Pointer()))
	}

	return &utlsQUICConn{
		conn:               q,
		uconn:              uconn,
		clientRandomPrefix: prefix,
		clientRandomMask:   mask,
	}
}

func (c *utlsQUICConn) patchClientRandom() {
	if len(c.clientRandomPrefix) == 0 || c.uconn == nil {
		return
	}
	if err := c.uconn.BuildHandshakeState(); err != nil {
		return
	}
	hello := c.uconn.HandshakeState.Hello
	if hello == nil || len(hello.Random) < 32 {
		return
	}
	prefixLen := len(c.clientRandomPrefix)
	if prefixLen > 32 {
		prefixLen = 32
	}
	for i := 0; i < prefixLen; i++ {
		mask := byte(0xff)
		if i < len(c.clientRandomMask) {
			mask = c.clientRandomMask[i]
		}
		hello.Random[i] = (c.clientRandomPrefix[i] & mask) | (hello.Random[i] & ^mask)
	}
	if len(hello.Raw) >= 38 {
		copy(hello.Raw[6:38], hello.Random)
	}
}

func (c *utlsQUICConn) Start(ctx context.Context) error {
	c.patchClientRandom()
	return c.conn.Start(ctx)
}

func (c *utlsQUICConn) Close() error { return c.conn.Close() }

func (c *utlsQUICConn) NextEvent() tls.QUICEvent { return c.conn.NextEvent() }

func (c *utlsQUICConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	return c.conn.HandleData(level, data)
}

func (c *utlsQUICConn) SetTransportParameters(params []byte) {
	c.conn.SetTransportParameters(params)
}

func (c *utlsQUICConn) ConnectionState() tls.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *utlsQUICConn) SendSessionTicket(opts tls.QUICSessionTicketOptions) error {
	return c.conn.SendSessionTicket(opts)
}

func (c *utlsQUICConn) StoreSession(_ *tls.SessionState) error {
	// UQUICConn не имеет StoreSession — no-op
	return nil
}
