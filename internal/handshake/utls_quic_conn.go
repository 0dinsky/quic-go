package handshake

import (
	"context"
	"crypto/tls"
	"unsafe"

	"github.com/sagernet/quic-go/internal/utils"

	utls "github.com/metacubex/utls"
)

// quicTLSConn — интерфейс для stdQUICConn и utlsQUICConn
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

// stdQUICConn оборачивает *tls.QUICConn
type stdQUICConn struct{ *tls.QUICConn }

func (c *stdQUICConn) StoreSession(session *tls.SessionState) error {
	return c.QUICConn.StoreSession(session)
}

// utlsQUICConn оборачивает *utls.UQUICConn с патчем client_random
type utlsQUICConn struct {
	conn               *utls.UQUICConn
	uconn              *utls.UConn
	clientRandomPrefix []byte
	clientRandomMask   []byte
	logger             utils.Logger
}

func newUTLSQUICConn(tlsConf *tls.Config, id utls.ClientHelloID, prefix, mask []byte, logger utils.Logger) *utlsQUICConn {
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

	// UQUICConn layout: первое поле — conn *UConn (unexported).
	// reflect.Value.Pointer() на unexported поле вызывает panic, поэтому
	// используем прямой unsafe-каст: разыменовываем первое слово структуры.
	uconn := *(**utls.UConn)(unsafe.Pointer(q))

	return &utlsQUICConn{
		conn:               q,
		uconn:              uconn,
		clientRandomPrefix: prefix,
		clientRandomMask:   mask,
		logger:             logger,
	}
}

func (c *utlsQUICConn) patchClientRandom() {
	if len(c.clientRandomPrefix) == 0 || c.uconn == nil {
		return
	}
	if err := c.uconn.BuildHandshakeState(); err != nil {
		c.logger.Errorf("utlsQUICConn: BuildHandshakeState failed: %v", err)
		return
	}
	hello := c.uconn.HandshakeState.Hello
	if hello == nil || len(hello.Random) < 32 {
		c.logger.Errorf("utlsQUICConn: Hello.Random not available after BuildHandshakeState")
		return
	}
	patched := make([]byte, 32)
	copy(patched, hello.Random)
	prefixLen := len(c.clientRandomPrefix)
	if prefixLen > 32 {
		prefixLen = 32
	}
	for i := 0; i < prefixLen; i++ {
		mask := byte(0xff)
		if i < len(c.clientRandomMask) {
			mask = c.clientRandomMask[i]
		}
		patched[i] = (c.clientRandomPrefix[i] & mask) | (patched[i] & ^mask)
	}
	if err := c.uconn.SetClientRandom(patched); err != nil {
		c.logger.Errorf("utlsQUICConn: SetClientRandom failed: %v", err)
		return
	}
	if c.uconn.ClientHelloID == utls.HelloGolang {
		// For HelloGolang the ClientHello is built via stdlib makeClientHello()
		// which correctly includes quic_transport_parameters (ext 57, RFC 9001).
		// Raw must be nil so stdlib marshalMsg() serializes the patched Random.
		c.uconn.HandshakeState.Hello.Raw = nil
		c.logger.Debugf("utlsQUICConn: client_random prefix patched (HelloGolang), prefix=%x", patched[:prefixLen])
		return
	}
	// For uTLS presets: re-marshal with patched Random via official API.
	if err := c.uconn.MarshalClientHello(); err != nil {
		c.logger.Errorf("utlsQUICConn: MarshalClientHello failed: %v", err)
		return
	}
	c.logger.Debugf("utlsQUICConn: client_random prefix patched (uTLS preset), prefix=%x", patched[:prefixLen])
}

func (c *utlsQUICConn) Start(ctx context.Context) error {
	c.patchClientRandom()
	return c.conn.Start(ctx)
}

func (c *utlsQUICConn) Close() error { return c.conn.Close() }

// NextEvent конвертирует utls.QUICEvent → crypto/tls.QUICEvent
func (c *utlsQUICConn) NextEvent() tls.QUICEvent {
	ev := c.conn.NextEvent()
	out := tls.QUICEvent{
		Kind:  tls.QUICEventKind(ev.Kind),
		Level: tls.QUICEncryptionLevel(ev.Level),
		Suite: ev.Suite,
		Data:  ev.Data,
	}
	if ev.SessionState != nil {
		out.SessionState = (*tls.SessionState)(unsafe.Pointer(ev.SessionState))
	}
	return out
}

func (c *utlsQUICConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	return c.conn.HandleData(utls.QUICEncryptionLevel(level), data)
}

func (c *utlsQUICConn) SetTransportParameters(params []byte) {
	c.conn.SetTransportParameters(params)
}

func (c *utlsQUICConn) ConnectionState() tls.ConnectionState {
	cs := c.conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		TLSUnique:                   cs.TLSUnique,
	}
}

func (c *utlsQUICConn) SendSessionTicket(opts tls.QUICSessionTicketOptions) error {
	return c.conn.SendSessionTicket(utls.QUICSessionTicketOptions{
		EarlyData: opts.EarlyData,
	})
}

func (c *utlsQUICConn) StoreSession(_ *tls.SessionState) error {
	return nil
}
