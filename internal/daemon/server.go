package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
)

// Server hosts both the local Web Console HTTP server and the CLI RPC server.
type Server struct {
	svc        *Service
	paths      config.Paths
	webLn      net.Listener
	rpcLn      net.Listener
	webSrv     *http.Server
	rpcSrv     *http.Server
	shutdownCh chan struct{}
	once       sync.Once
}

// StartServer binds loopback Web UI + session RPC socket/port and serves until stopped.
func StartServer(ctx context.Context, paths config.Paths, version, commit, webPort string) (*Server, error) {
	svc, err := NewService(ctx, paths, version, commit)
	if err != nil {
		return nil, err
	}

	if webPort == "" {
		webPort = os.Getenv(config.EnvWebPort)
	}
	bindAddr := "127.0.0.1:0"
	if webPort != "" {
		bindAddr = "127.0.0.1:" + webPort
	}
	webLn, err := net.Listen("tcp", bindAddr)
	if err != nil {
		svc.Shutdown()
		return nil, fmt.Errorf("listen web %s: %w", bindAddr, err)
	}
	webURL := "http://" + webLn.Addr().String()
	svc.SetWebURL(webURL)

	rpcLn, rpcAddr, rpcToken, err := ListenRPC(paths)
	if err != nil {
		_ = webLn.Close()
		svc.Shutdown()
		return nil, fmt.Errorf("listen rpc: %w", err)
	}

	srv := &Server{
		svc:        svc,
		paths:      paths,
		webLn:      webLn,
		rpcLn:      rpcLn,
		shutdownCh: make(chan struct{}),
	}

	srv.webSrv = &http.Server{
		Handler:           NewWebHandler(svc),
		ReadHeaderTimeout: 5 * time.Second,
	}
	rpcHandler := NewRPCHandler(svc, srv.TriggerShutdown)
	srv.rpcSrv = &http.Server{
		Handler:           wrapPlatformRPCHandler(rpcToken, rpcHandler),
		ReadHeaderTimeout: 5 * time.Second,
	}

	if err := WriteDaemonMeta(paths, DaemonMeta{
		Version:   version,
		Commit:    commit,
		PID:       os.Getpid(),
		Session:   paths.Session,
		RPCAddr:   rpcAddr,
		RPCToken:  rpcToken,
		WebURL:    webURL,
		StartedAt: svc.Identity().StartedAt,
	}); err != nil {
		_ = webLn.Close()
		_ = rpcLn.Close()
		svc.Shutdown()
		return nil, err
	}

	return srv, nil
}

// WebURL returns the active Web Console URL.
func (s *Server) WebURL() string {
	return s.svc.Identity().WebURL
}

// Service returns the underlying daemon service (useful for tests).
func (s *Server) Service() *Service {
	return s.svc
}

// TriggerShutdown signals the server to drain and exit.
func (s *Server) TriggerShutdown() {
	s.once.Do(func() {
		close(s.shutdownCh)
	})
}

// Run serves HTTP/RPC until ctx cancellation, OS signal, or RPC shutdown.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.webSrv.Serve(s.webLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := s.rpcSrv.Serve(s.rpcLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	var runErr error
	select {
	case <-ctx.Done():
	case <-sigCh:
	case <-s.shutdownCh:
	case e := <-errCh:
		runErr = e
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.rpcSrv.Shutdown(shutCtx)
	_ = s.webSrv.Shutdown(shutCtx)
	wg.Wait()
	_ = os.Remove(s.paths.SocketPath)
	_ = os.Remove(s.paths.DaemonMeta)
	s.svc.Shutdown()
	return runErr
}
