package handshake

import (
	"context"
	"crypto/tls"
	"io"
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

// patchedRand реализует io.Reader с патчем Client Random
type patchedRand struct {
	r      io.Reader
	prefix []byte
	mask   []byte
	done   bool
}

func (pr *patchedRand) Read(p []byte) (n int, err error) {
	n, err = pr.r.Read(p)
	// Первое чтение на 32 байта в клиенте — это ClientRandom
	if !pr.done && len(p) == 32 && n == 32 {
		prefixLen := len(pr.prefix)
		if prefixLen > 32 {
			prefixLen = 32
		}
		for i := 0; i < prefixLen; i++ {
			m := byte(0xff)
			if i < len(pr.mask) {
				m = pr.mask[i]
			}
			p[i] = (pr.prefix[i] & m) | (p[i] & ^m)
		}
		pr.done = true
	}
	return n, err
}

// utlsQUICConn оборачивает *utls.UQUICConn с патчем client_random
type utlsQUICConn struct {
	conn   *utls.UQUICConn
	logger utils.Logger
}

func newUTLSQUICConn(tlsConf *tls.Config, id utls.ClientHelloID, prefix, mask []byte, logger utils.Logger) *utlsQUICConn {
	// Создаем патченный Rand для внедрения клиентского рандома
	patchedRand := &patchedRand{
		r:      tlsConf.Rand, // если nil, внутри uTLS будет использован crypto/rand.Reader
		prefix: prefix,
		mask:   mask,
	}
	
	cfg := &utls.QUICConfig{
		TLSConfig: &utls.Config{
			ServerName:             tlsConf.ServerName,
			RootCAs:                tlsConf.RootCAs,
			NextProtos:             tlsConf.NextProtos,
			InsecureSkipVerify:     tlsConf.InsecureSkipVerify,
			MinVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: tlsConf.SessionTicketsDisabled,
			Rand:                   patchedRand, // внедряем патченный Rand
		},
		EnableSessionEvents: true,
	}
	
	return &utlsQUICConn{
		conn:   utls.UQUICClient(cfg, id),
		logger: logger,
	}
}

func (c *utlsQUICConn) Start(ctx context.Context) error {
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

func (c *utlsQUICConn) StoreSession(session *tls.SessionState) error {
	// uTLS UQUICConn не имеет метода StoreSession, поэтому просто возвращаем nil
	// Если нужна поддержка хранения сессий, можно реализовать через unsafe,
	// но обычно для QUIC с uTLS это не требуется
	return nil
}
