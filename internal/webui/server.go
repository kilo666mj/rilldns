package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var assets embed.FS

func New(api http.Handler, config OIDCConfig) (http.Handler, error) {
	if err := validateOIDC(config); err != nil {
		return nil, err
	}
	auth, err := newAuth(config)
	if err != nil {
		return nil, err
	}
	static, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", func(writer http.ResponseWriter, request *http.Request) {
		if auth.Valid(request) {
			http.Redirect(writer, request, "/", http.StatusFound)
			return
		}
		http.ServeFileFS(writer, request, static, "login.html")
	})
	mux.HandleFunc("GET /api/auth/login/start", auth.oidc.LoginStart)
	mux.HandleFunc("GET /api/auth/callback", auth.oidc.Callback)
	mux.HandleFunc("POST /api/auth/logout", func(writer http.ResponseWriter, request *http.Request) {
		auth.Clear(writer, request)
		http.Redirect(writer, request, "/login", http.StatusFound)
	})
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/v1/", auth.oidc.Require(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Header.Set("X-RillDNS-Actor", auth.actor(request))
		api.ServeHTTP(writer, request)
	})))
	mux.Handle("GET /{$}", auth.oidc.Require(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.ServeFileFS(writer, request, static, "index.html")
	})))
	return securityHeaders(mux), nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}
