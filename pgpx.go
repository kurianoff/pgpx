package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/kurianoff/pgpx/pgproxy"
)

var (
	versionNumber string
)

type tlsLogicalConn struct {
	net.Conn
}

func (c *tlsLogicalConn) Cancel(data *pgproxy.CancelData) error {
	// Implement the cancel logic if necessary or return nil
	// For this example, we'll just return nil since we're not handling cancel requests
	return nil
}

func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// IMPORTANT: In production, set InsecureSkipVerify to false and setup proper CA verification
		InsecureSkipVerify: true,
	}

	return config, nil
}

func fetchDynamicPassword(cmdStr string) (string, error) {
	cmd := exec.Command("bash", "-c", cmdStr)

	// Replace with your shell command to fetch the dynamic password
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Msgf("Error executing command: %+v", err)
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func dialBackendWithDynamicPassword(ctx context.Context, startupData *pgproxy.StartupData, pgHostPort string, credsCmd string, credsOverride bool, ignoreUsername bool) (pgproxy.LogicalConn, error) {
	// if ignoreUsername flag not set: find matching username in credsCmd, otherwise do not override password
	overrideCredentials := credsOverride && (ignoreUsername || strings.Contains(strings.ToLower(credsCmd), strings.ToLower(startupData.Username)))
	log.Trace().Msgf("Override credentials: %t", overrideCredentials)

	if overrideCredentials {
		dynamicPassword, err := fetchDynamicPassword(credsCmd)
		if err != nil {
			log.Error().Msgf("Error retrieving dynamic password: %+v", err)
			return nil, err
		}
		startupData.Password = dynamicPassword
	}

	conn, err := net.Dial("tcp", pgHostPort)
	if err != nil {
		log.Error().Msgf("Error connecting to the PostgreSQL backend: %+v", err)
		return nil, err
	}

	log.Trace().Msg("Connection with the PostgreSQL backend has been established.")
	return &tlsLogicalConn{conn}, nil
}

func main() {
	proxyHost := flag.String("proxyHost", "localhost", "Host where pgpx is accepting connections")
	proxyPort := flag.String("proxyPort", "6432", "Port where pgpx is accepting connections")
	pgHostPort := flag.String("pgHostPort", "", "Hostname and port of the PostgreSQL server, e.g. \"localhost:5432\" (required)")
	dbCertPath := flag.String("dbCertPath", "", "Absolute path to the database SSL CA certificate (required)")
	credsCmd := flag.String("credsCmd", "", "Bash command to retrieve temporary database connection password")
	credsOverride := flag.Bool("credsOverride", true, "Indicates whether to override the password provided through the client application")
	ignoreUsername := flag.Bool("ignoreUsername", false, "By default, the tool matches provided username with the one in credsCmd command to decide on overriding the password. Set this flag to ignore username matching.")
	version := flag.Bool("version", false, "Show pgpx version information")

	// Parse the command-line arguments
	flag.Parse()

	if *version == true {
		fmt.Println(versionNumber)
		return
	}

	if (*credsOverride && *credsCmd == "") || *pgHostPort == "" || *dbCertPath == "" {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		return
	}

	proxyHostPort := fmt.Sprintf("%s:%s", *proxyHost, *proxyPort)

	// Uncomment the following lines if you want the client app to use TLS connection
	//
	// tlsConfig, err := loadTLSConfig("path_to_cert.crt", "path_to_key.key")
	// if err != nil {
	// 	log.Fatalf("Failed to load TLS config: %v", err)
	// }

	ln, err := net.Listen("tcp", proxyHostPort)
	if err != nil {
		log.Error().Msgf("Failed to start listener: %+v", err)
	}

	rootCertPool := x509.NewCertPool()
	pem, err := ioutil.ReadFile(*dbCertPath)
	if err != nil {
		log.Error().Msgf("Failed to load root CA certificate: %+v", err)
		return
	}
	if !rootCertPool.AppendCertsFromPEM(pem) {
		log.Error().Msgf("No certs found in root CA certificate")
		return
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		// If you're using a self-signed certificate or a certificate from a CA that's not
		// in the system's root certificate store, you'll need to add it here.
		RootCAs: rootCertPool,

		// Uncomment and set these if client-side certificate authentication is required by PostgreSQL.
		// Certificates: []tls.Certificate{clientCert},
	}

	proxy := &pgproxy.SingleBackendProxy{
		RequirePassword: true,
		FrontendTLS:     nil,
		BackendTLS:      tlsConfig,
	}

	proxy.DialBackend = func(ctx context.Context, startupData *pgproxy.StartupData) (pgproxy.LogicalConn, error) {
		return dialBackendWithDynamicPassword(ctx, startupData, *pgHostPort, *credsCmd, *credsOverride, *ignoreUsername)
	}

	log.Trace().Msgf("Starting PostgreSQL proxy on %s ...", proxyHostPort)
	err = proxy.Serve(context.Background(), ln)
	if err != nil {
		log.Error().Msgf("Failed to start proxy: %+v", err)
	}
}
