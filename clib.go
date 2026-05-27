package main

/*
#include <stdlib.h>
*/
import "C"

import (
    "context"
    "crypto/tls"
    "errors"
    "net"
    "sync"
    "time"
    "unsafe"

    "github.com/RedTeamPentesting/resocks/proxyrelay"
)

// ── state ─────────────────────────────────────────────────────────────────────

var (
    mu           sync.Mutex
    activeCancel context.CancelFunc
    lastErrStr   string
)

func setLastErr(err error) {
    mu.Lock()
    defer mu.Unlock()
    if err != nil {
        lastErrStr = err.Error()
    } else {
        lastErrStr = ""
    }
}

// ── exports ────────────────────────────────────────────────────────────────────

//export ResocksStartRelay
// ResocksStartRelay connects back to a resocks listener and relays SOCKS5 traffic.
//   connectBackAddr : "192.0.2.1:4080"
//   key             : shared connection key from `resocks generate`
//   timeoutSec      : dial timeout in seconds (5 is a good default)
//   reconnectSec    : seconds between reconnect attempts; 0 = no reconnect
//   insecure        : 1 = skip server cert check, 0 = full mTLS
// Returns 0 on success, -1 if already running.
func ResocksStartRelay(connectBackAddr *C.char, key *C.char,
    timeoutSec C.int, reconnectSec C.int, insecure C.int) C.int {

    mu.Lock()
    if activeCancel != nil {
        mu.Unlock()
        return -1
    }
    ctx, cancel := context.WithCancel(context.Background())
    activeCancel = cancel
    mu.Unlock()

    addr := C.GoString(connectBackAddr)
    k    := C.GoString(key)
    to   := time.Duration(timeoutSec) * time.Second
    rc   := time.Duration(reconnectSec) * time.Second
    ins  := insecure != 0

    go func() {
        defer func() {
            mu.Lock()
            activeCancel = nil
            mu.Unlock()
        }()
        err := relayWithContext(ctx, withDefaultPort(addr, DefaultListenPort), k, to, rc, ins)
        setLastErr(err)
    }()

    return 0
}

//export ResocksStartListener
// ResocksStartListener waits for a relay to connect back and exposes SOCKS5.
//   listenAddr : address to accept reverse connections on, e.g. ":4080"
//   socksAddr  : address to expose SOCKS5 on, e.g. ":1080"
//   key        : shared connection key (empty = auto-generate, but you won't know it)
//   insecure   : 1 = skip client cert check, 0 = full mTLS
// Returns 0 on success, -1 if already running.
func ResocksStartListener(listenAddr *C.char, socksAddr *C.char,
    key *C.char, insecure C.int) C.int {

    mu.Lock()
    if activeCancel != nil {
        mu.Unlock()
        return -1
    }
    ctx, cancel := context.WithCancel(context.Background())
    activeCancel = cancel
    mu.Unlock()

    la  := C.GoString(listenAddr)
    sa  := C.GoString(socksAddr)
    k   := C.GoString(key)
    ins := insecure != 0

    go func() {
        defer func() {
            mu.Lock()
            activeCancel = nil
            mu.Unlock()
        }()
        err := listenHeadless(
            ctx,
            withDefaultPort(la, DefaultListenPort),
            withDefaultPort(sa, DefaultProxyPort),
            k, ins,
        )
        setLastErr(err)
    }()

    return 0
}

//export ResocksStop
// ResocksStop cancels the running relay or listener.
func ResocksStop() {
    mu.Lock()
    cancel := activeCancel
    mu.Unlock()

    if cancel != nil {
        cancel()
    }
}

//export ResocksLastError
// ResocksLastError returns the last error as a C string.
// The caller MUST pass the returned pointer to ResocksFree().
func ResocksLastError() *C.char {
    mu.Lock()
    defer mu.Unlock()
    return C.CString(lastErrStr)
}

//export ResocksFree
// ResocksFree releases a string returned by ResocksLastError.
func ResocksFree(p *C.char) {
    C.free(unsafe.Pointer(p))
}

// ── headless implementations ──────────────────────────────────────────────────

// relayWithContext replaces connectBackAndRelay() from relay.go.
// The original calls proxyrelay.RunRelay(context.Background(), conn) which
// ignores cancellation. This version passes ctx through correctly.
func relayWithContext(
    ctx context.Context,
    connectBackAddr, connectionKey string,
    timeout, reconnectAfter time.Duration,
    insecure bool,
) error {
    tlsConfig, err := clientTLSConfig(connectionKey, insecure) // from relay.go
    if err != nil {
        return err
    }

    for {
        if ctx.Err() != nil {
            return nil
        }

        conn, err := tls.DialWithDialer(
            &net.Dialer{Timeout: timeout},
            "tcp", connectBackAddr, tlsConfig,
        )
        if err != nil {
            if ctx.Err() != nil {
                return nil
            }
            if reconnectAfter == 0 {
                return err
            }
            select {
            case <-ctx.Done():
                return nil
            case <-time.After(reconnectAfter):
                continue
            }
        }

        // Close conn when ctx is cancelled so RunRelay unblocks.
        stopWatch := make(chan struct{})
        go func() {
            select {
            case <-ctx.Done():
                conn.Close()
            case <-stopWatch:
            }
        }()

        err = proxyrelay.RunRelay(ctx, conn)
        close(stopWatch)
        conn.Close()

        if ctx.Err() != nil {
            return nil
        }
        if reconnectAfter == 0 {
            return err
        }
        select {
        case <-ctx.Done():
            return nil
        case <-time.After(reconnectAfter):
        }
    }
}

// listenHeadless replaces runLocalSocksProxy() from listen.go.
// The original starts a bubbletea TUI which requires a terminal and will
// panic inside a DLL. This version is pure networking, no UI.
func listenHeadless(
    ctx context.Context,
    listenAddr, proxyAddr, connectionKey string,
    insecure bool,
) error {
    tlsConfig, _, err := serverTLSConfig(connectionKey, insecure) // from listen.go
    if err != nil {
        return err
    }

    listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
    if err != nil {
        return err
    }
    defer listener.Close()

    // Close listener when ctx is cancelled so Accept() unblocks.
    go func() {
        <-ctx.Done()
        listener.Close()
    }()

    for {
        relayConn, err := listener.Accept()
        if err != nil {
            if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
                return nil
            }
            return err
        }

        // Each relay connection is served in its own goroutine;
        // the listener keeps accepting new ones if the relay reconnects.
        go func(conn net.Conn) {
            defer conn.Close()
            // nil callback = silent, no stdout/stderr noise from the DLL.
            _ = proxyrelay.RunProxyWithEventCallback(ctx, conn, proxyAddr, nil)
        }(relayConn)
    }
}

// main is required by c-archive but is never called.
func main() {}