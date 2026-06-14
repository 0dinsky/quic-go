package handshake

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"reflect"
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

	var uconn *utls.UConn
	v := reflect.ValueOf(q).Elem()
	if f := v.FieldByName("conn"); f.IsValid() {
		uconn = (*utls.UConn)(unsafe.Pointer(f.Pointer()))
	}

	if logger != nil {
		logger.Debugf("trusttunnel-debug: newUTLSQUICConn uconn_nil=%v prefix=%x mask=%x", uconn == nil, prefix, mask)
	}

	return &utlsQUICConn{
		conn:               q,
		uconn:              uconn,
		clientRandomPrefix: prefix,
		clientRandomMask:   mask,
		logger:             logger,
	}
}

func (c *utlsQUICConn) patchClientRandom() {
	if c.logger != nil {
		c.logger.Debugf("trusttunnel-debug: patchClientRandom called, prefixLen=%d uconn_nil=%v", len(c.clientRandomPrefix), c.uconn == nil)
	}
	if len(c.clientRandomPrefix) == 0 || c.uconn == nil {
		return
	}
	if err := c.uconn.BuildHandshakeState(); err != nil {
		if c.logger != nil {
			c.logger.Debugf("trusttunnel-debug: BuildHandshakeState error: %v", err)
		}
		return
	}
	hello := c.uconn.HandshakeState.Hello
	if hello == nil || len(hello.Random) < 32 {
		if c.logger != nil {
			c.logger.Debugf("trusttunnel-debug: hello nil or random too short, hello_nil=%v", hello == nil)
		}
		return
	}
	// Копируем текущий Random и патчим prefix с маской (как в TCP-пути).
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
		if c.logger != nil {
			c.logger.Debugf("trusttunnel-debug: SetClientRandom error: %v", err)
		}
		return
	}
	// SetClientRandom обновляет только HandshakeState.Hello.Random.
	// Hello.Raw уже был замаршален с оригинальным Random при первом BuildHandshakeState.
	// Пересобираем Raw полностью через официальный API utls, который заново
	// сериализует весь ClientHello (включая обновлённый Random).
	if err := c.uconn.MarshalClientHello(); err != nil {
		if c.logger != nil {
			c.logger.Debugf("trusttunnel-debug: MarshalClientHello error: %v", err)
		}
		return
	}
	if c.logger != nil {
		c.logger.Debugf("trusttunnel-debug: patched. Random[0:4]=%s Raw[6:10]=%s", hex.EncodeToString(c.uconn.HandshakeState.Hello.Random[:4]), hex.EncodeToString(c.uconn.HandshakeState.Hello.Raw[6:10]))
	}
}

func (c *utlsQUICConn) Start(ctx context.Context) error {
	c.patchClientRandom()
	return c.conn.Start(ctx)
}

func (c *utlsQUICConn) Close() error { return c.conn.Close() }

// NextEvent конвертирует utls.QUICEvent → crypto/tls.QUICEvent
// utls.QUICEventKind и tls.QUICEventKind — оба int, конвертируем напрямую.
// utls.QUICEncryptionLevel и tls.QUICEncryptionLevel — оба int, аналогично.
func (c *utlsQUICConn) NextEvent() tls.QUICEvent {
	ev := c.conn.NextEvent()
	if ev.Kind == utls.QUICWriteData && len(ev.Data) >= 6 && c.logger != nil {
		dataLen := len(ev.Data)
		preview := dataLen
		if preview > 10 {
			preview = 10
		}
		c.logger.Debugf("trusttunnel-debug: NextEvent WriteData level=%d len=%d data[0:%d]=%s", ev.Level, dataLen, preview, hex.EncodeToString(ev.Data[:preview]))
		if c.uconn != nil && c.uconn.HandshakeState.Hello != nil {
			h := c.uconn.HandshakeState.Hello
			if len(h.Raw) >= 38 {
				c.logger.Debugf("trusttunnel-debug: at NextEvent Hello.Raw[6:10]=%s Random[0:4]=%s", hex.EncodeToString(h.Raw[6:10]), hex.EncodeToString(h.Random[:4]))
			}
		}
	}
	out := tls.QUICEvent{
		Kind:  tls.QUICEventKind(ev.Kind),
		Level: tls.QUICEncryptionLevel(ev.Level),
		Data:  ev.Data,
	}
	if ev.SessionState != nil {
		// utls.SessionState и crypto/tls.SessionState имеют идентичный layout
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
