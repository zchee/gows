// Copyright 2026 The gows Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gows

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// countWriteConn wraps an arbitrary net.Conn and counts the Write calls issued
// to it, forwarding every method to the wrapped conn. It is used to count the
// Writes gows issues to a live transport (for example a crypto/tls.Conn),
// unlike countingConn, which embeds the in-memory scriptConn.
type countWriteConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *countWriteConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

// TestVectoredDetection locks the construction-time transport classification:
// the two stdlib stream types that give net.Buffers a real writev are marked
// vectored, and every other net.Conn falls back to the staged single-Write
// path.
func TestVectoredDetection(t *testing.T) {
	t.Parallel()

	t.Run("tcp is vectored", func(t *testing.T) {
		t.Parallel()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		dialed, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer dialed.Close()
		accepted, err := ln.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		defer accepted.Close()
		if _, ok := accepted.(*net.TCPConn); !ok {
			t.Fatalf("accepted conn is %T, want *net.TCPConn", accepted)
		}
		if c := NewServerConn(accepted); !c.vectored {
			t.Errorf("*net.TCPConn: vectored=false, want true")
		}
	})

	t.Run("unix is vectored", func(t *testing.T) {
		t.Parallel()
		// A short base keeps the socket path within the platform sun_path limit
		// (~104 bytes on darwin), which t.TempDir's long path would exceed.
		dir, err := os.MkdirTemp("/tmp", "gows")
		if err != nil {
			if dir, err = os.MkdirTemp("", "gows"); err != nil {
				t.Fatalf("mkdir temp: %v", err)
			}
		}
		defer os.RemoveAll(dir)
		sock := filepath.Join(dir, "s")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			// The *net.UnixConn detection is a compile-time type-switch case; if
			// this environment cannot bind a unix socket, skip rather than fail.
			t.Skipf("unix socket unavailable in this environment: %v", err)
		}
		defer ln.Close()
		dialed, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial unix: %v", err)
		}
		defer dialed.Close()
		accepted, err := ln.Accept()
		if err != nil {
			t.Fatalf("accept unix: %v", err)
		}
		defer accepted.Close()
		if _, ok := accepted.(*net.UnixConn); !ok {
			t.Fatalf("accepted conn is %T, want *net.UnixConn", accepted)
		}
		if c := NewClientConn(dialed); !c.vectored {
			t.Errorf("*net.UnixConn: vectored=false, want true")
		}
	})

	t.Run("other conns are not vectored", func(t *testing.T) {
		t.Parallel()
		if c := NewServerConn(&scriptConn{}); c.vectored {
			t.Errorf("scriptConn: vectored=true, want false")
		}
		if c := NewServerConn(&loopConn{}); c.vectored {
			t.Errorf("loopConn: vectored=true, want false")
		}
		if c := NewServerConn(&countWriteConn{Conn: &scriptConn{}}); c.vectored {
			t.Errorf("wrapped scriptConn: vectored=true, want false")
		}
	})
}

// TestWriteMessageStagedSingleWrite proves the staged (non-writev) path issues
// exactly one Write per message on a transport where net.Buffers would
// otherwise degrade to two write syscalls (one per buffer).
func TestWriteMessageStagedSingleWrite(t *testing.T) {
	t.Parallel()

	sizes := map[string]int{
		"4KiB":  4 << 10,
		"16KiB": 16 << 10,
		"64KiB": 64 << 10,
	}
	for name, size := range sizes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wire := &countingConn{scriptConn: &scriptConn{}}
			c := NewServerConn(wire)
			if c.vectored {
				t.Fatalf("countingConn wrongly detected as vectored")
			}
			payload := bytes.Repeat([]byte{0x5a}, size)
			if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
				t.Fatalf("WriteMessage: %v", err)
			}
			if wire.writes != 1 {
				t.Fatalf("underlying writes = %d, want 1 (staged single write)", wire.writes)
			}
			frames := parseFrames(t, wire.out.Bytes())
			if len(frames) != 1 || frames[0].h.Opcode != OpcodeBinary || !bytes.Equal(frames[0].payload, payload) {
				t.Fatalf("frame mismatch: frames=%d", len(frames))
			}
		})
	}
}

// TestWriteMessageStagedClientSingleWrite proves the client masking path also
// reaches the socket in one Write on a non-writev transport: the header and
// masked payload are staged contiguously.
func TestWriteMessageStagedClientSingleWrite(t *testing.T) {
	t.Parallel()

	wire := &countingConn{scriptConn: &scriptConn{}}
	c := NewClientConn(wire)
	if c.vectored {
		t.Fatalf("countingConn wrongly detected as vectored")
	}
	payload := bytes.Repeat([]byte{0x5a}, 16<<10)
	orig := bytes.Clone(payload)
	if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	if wire.writes != 1 {
		t.Fatalf("underlying writes = %d, want 1 (staged single write)", wire.writes)
	}
	frames := parseFrames(t, wire.out.Bytes())
	if len(frames) != 1 || !frames[0].h.Masked || !bytes.Equal(frames[0].payload, payload) {
		t.Fatalf("client frame not masked / wrong payload")
	}
	if !bytes.Equal(payload, orig) {
		t.Errorf("client WriteMessage mutated caller's payload")
	}
}

// TestWriteMessageStagedOverflowTwoWrites documents the >cap behavior: a
// message whose header+payload exceeds maxBufferedWriteSize is sent as the
// cap-sized staged prefix followed by the payload remainder -- two Writes,
// which bounds the staging scratch.
func TestWriteMessageStagedOverflowTwoWrites(t *testing.T) {
	t.Parallel()

	wire := &countingConn{scriptConn: &scriptConn{}}
	c := NewServerConn(wire)
	// One byte past the cap forces the overflow split; the header pushes the
	// total further over, so the payload remainder is written directly.
	payload := bytes.Repeat([]byte{0x33}, maxBufferedWriteSize+1)
	if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	if wire.writes != 2 {
		t.Fatalf("underlying writes = %d, want 2 (staged prefix + remainder)", wire.writes)
	}
	frames := parseFrames(t, wire.out.Bytes())
	if len(frames) != 1 || frames[0].h.Opcode != OpcodeBinary || !bytes.Equal(frames[0].payload, payload) {
		t.Fatalf("frame reassembled from two writes is wrong: frames=%d", len(frames))
	}
	// The staging scratch must stay bounded to the pool's largest size class.
	if cap(c.wstage) > maxBufferedWriteSize {
		t.Errorf("wstage cap = %d, want <= %d", cap(c.wstage), maxBufferedWriteSize)
	}
}

// TestWriteMessageStaged16KBZeroAllocs extends the allocation suite to the
// staged path: after warmup the pooled staging scratch is reused, so a 16 KiB
// message frames and writes with zero steady-state allocations.
func TestWriteMessageStaged16KBZeroAllocs(t *testing.T) {
	c := NewServerConn(&loopConn{frame: []byte{0x00}})
	if c.vectored {
		t.Fatalf("loopConn wrongly detected as vectored")
	}
	payload := bytes.Repeat([]byte{0x41}, 16<<10)
	for range 8 { // warm up the staging scratch to its steady-state capacity
		if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	}
	allocs := testing.AllocsPerRun(500, func() {
		_ = c.WriteMessage(OpcodeBinary, payload)
	})
	t.Logf("staged 16 KiB WriteMessage allocs/op = %v (race=%v)", allocs, raceEnabledInternal)
	if !raceEnabledInternal && allocs != 0 {
		t.Errorf("staged 16 KiB WriteMessage allocs/op = %v, want 0", allocs)
	}
}

// TestWriteMessageTLSSingleWrite is the production-shaped robustness case: a
// gows server writing over a crypto/tls.Conn must issue exactly one Write to
// that tls.Conn per message. The counter wraps the tls.Conn that gows writes
// to, so it sees gows-issued application Writes, not the TLS records the tls
// layer emits beneath it.
func TestWriteMessageTLSSingleWrite(t *testing.T) {
	t.Parallel()

	cert := selfSignedCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-ch
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}

	serverTLS := tls.Server(a.c, &tls.Config{Certificates: []tls.Certificate{cert}})
	clientTLS := tls.Client(rawClient, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only self-signed loopback

	// Drive both handshake halves concurrently so neither side blocks the other.
	hs := make(chan error, 2)
	go func() { hs <- serverTLS.Handshake() }()
	go func() { hs <- clientTLS.Handshake() }()
	for range 2 {
		if err := <-hs; err != nil {
			t.Fatalf("tls handshake: %v", err)
		}
	}

	counter := &countWriteConn{Conn: serverTLS}
	srv := NewServerConn(counter)
	cli := NewClientConn(clientTLS)
	if srv.vectored {
		t.Fatalf("gows over a tls.Conn wrapper wrongly detected as vectored")
	}

	const n = 8
	msg := bytes.Repeat([]byte{0x41}, 16<<10)

	srvErr := make(chan error, 1)
	go func() {
		for range n {
			op, p, err := srv.ReadMessage()
			if err != nil {
				srvErr <- err
				return
			}
			if err := srv.WriteMessage(op, p); err != nil {
				srvErr <- err
				return
			}
		}
		srvErr <- nil
	}()

	for range n {
		if err := cli.WriteMessage(OpcodeBinary, msg); err != nil {
			t.Fatalf("client write: %v", err)
		}
		op, got, err := cli.ReadMessage()
		if err != nil {
			t.Fatalf("client read: %v", err)
		}
		if op != OpcodeBinary || !bytes.Equal(got, msg) {
			t.Fatalf("echo mismatch: op=%v len(got)=%d", op, len(got))
		}
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server echo: %v", err)
	}

	if got := counter.writes.Load(); got != n {
		t.Fatalf("server tls.Conn writes = %d, want %d (1 per echoed 16 KiB message)", got, n)
	}

	_ = clientTLS.Close()
	_ = serverTLS.Close()
}

// selfSignedCert builds an in-memory self-signed ECDSA certificate valid for
// the loopback host, so the TLS robustness test needs no on-disk key material.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gows-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
