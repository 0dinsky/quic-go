package handshake

import (
	"context"
	"crypto/tls"
	"reflect"
	"unsafe"

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
			// utls (Go 1.24 fork) includes X25519MLKEM768 (0x11ec) by default.
			// Most servers (quiche, older BoringSSL, rustls) silently drop
			// ClientHellos with this 1216-byte key share. Explicitly limit to
			// classical curves, or propagate caller's CurvePreferences if set.
			CurvePreferences: curvePrefsFromStdlib(tlsConf.CurvePreferences),
		},
		EnableSessionEvents: true,
	}
	q := utls.UQUICClient(cfg, id)

	var uconn *utls.UConn
	v := reflect.ValueOf(q).Elem()
	if f := v.FieldByName("conn"); f.IsValid() {
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
	// Patch IN PLACE: hello.Random shares its underlying array with the private
	// clientHelloMsg.random field (getPublicPtr copies the slice header, not the data).
	// Modifying bytes in-place keeps both in sync.
	// DO NOT use SetClientRandom — it replaces the slice header in the public struct
	// with a new allocation, leaving clientHelloMsg.random pointing to the original
	// (unpatched) array. marshal() then serialises the unpatched random.
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
	if c.uconn.ClientHelloID == utls.HelloGolang {
		// For HelloGolang the ClientHello is built via stdlib makeClientHello()
		// which correctly includes quic_transport_parameters (ext 57, RFC 9001).
		// Raw must be nil so stdlib marshalMsg() serializes the patched Random.
		c.uconn.HandshakeState.Hello.Raw = nil
		return
	}
	// For uTLS presets: re-marshal with patched Random via official API.
	_ = c.uconn.MarshalClientHello()
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

// curvePrefsFromStdlib converts []tls.CurveID → []utls.CurveID.
// If the caller set explicit preferences, they are propagated as-is.
// Otherwise a classical-only default is returned, intentionally excluding
// X25519MLKEM768 (0x11ec) which was added in Go 1.24 / utls but is not
// yet supported by many QUIC servers and causes silent handshake failures.
func curvePrefsFromStdlib(prefs []tls.CurveID) []utls.CurveID {
	if len(prefs) > 0 {
		out := make([]utls.CurveID, len(prefs))
		for i, c := range prefs {
			out[i] = utls.CurveID(c)
		}
		return out
	}
	return []utls.CurveID{
		utls.X25519,
		utls.CurveP256,
		utls.CurveP384,
		utls.CurveP521,
	}
}
