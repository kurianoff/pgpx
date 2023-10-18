package pgproxy

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"

	"encr.dev/pkg/fns"
)

// The below code is taken from github.com/encoredev/pgproxy (pgproxy.go).
// The code was slightly modified to enable SingleProxyBackend connection to underlying postgresql server.

/*
Copyright (c) 2023 Encore

Mozilla Public License, version 2.0

1. Definitions

1.1. "Contributor"

     means each individual or legal entity that creates, contributes to the
     creation of, or owns Covered Software.

1.2. "Contributor Version"

     means the combination of the Contributions of others (if any) used by a
     Contributor and that particular Contributor's Contribution.

1.3. "Contribution"

     means Covered Software of a particular Contributor.

1.4. "Covered Software"

     means Source Code Form to which the initial Contributor has attached the
     notice in Exhibit A, the Executable Form of such Source Code Form, and
     Modifications of such Source Code Form, in each case including portions
     thereof.

1.5. "Incompatible With Secondary Licenses"
     means

     a. that the initial Contributor has attached the notice described in
        Exhibit B to the Covered Software; or

     b. that the Covered Software was made available under the terms of
        version 1.1 or earlier of the License, but not also under the terms of
        a Secondary License.

1.6. "Executable Form"

     means any form of the work other than Source Code Form.

1.7. "Larger Work"

     means a work that combines Covered Software with other material, in a
     separate file or files, that is not Covered Software.

1.8. "License"

     means this document.

1.9. "Licensable"

     means having the right to grant, to the maximum extent possible, whether
     at the time of the initial grant or subsequently, any and all of the
     rights conveyed by this License.

1.10. "Modifications"

     means any of the following:

     a. any file in Source Code Form that results from an addition to,
        deletion from, or modification of the contents of Covered Software; or

     b. any new file in Source Code Form that contains any Covered Software.

1.11. "Patent Claims" of a Contributor

      means any patent claim(s), including without limitation, method,
      process, and apparatus claims, in any patent Licensable by such
      Contributor that would be infringed, but for the grant of the License,
      by the making, using, selling, offering for sale, having made, import,
      or transfer of either its Contributions or its Contributor Version.

1.12. "Secondary License"

      means either the GNU General Public License, Version 2.0, the GNU Lesser
      General Public License, Version 2.1, the GNU Affero General Public
      License, Version 3.0, or any later versions of those licenses.

1.13. "Source Code Form"

      means the form of the work preferred for making modifications.

1.14. "You" (or "Your")

      means an individual or a legal entity exercising rights under this
      License. For legal entities, "You" includes any entity that controls, is
      controlled by, or is under common control with You. For purposes of this
      definition, "control" means (a) the power, direct or indirect, to cause
      the direction or management of such entity, whether by contract or
      otherwise, or (b) ownership of more than fifty percent (50%) of the
      outstanding shares or beneficial ownership of such entity.


2. License Grants and Conditions

2.1. Grants

     Each Contributor hereby grants You a world-wide, royalty-free,
     non-exclusive license:

     a. under intellectual property rights (other than patent or trademark)
        Licensable by such Contributor to use, reproduce, make available,
        modify, display, perform, distribute, and otherwise exploit its
        Contributions, either on an unmodified basis, with Modifications, or
        as part of a Larger Work; and

     b. under Patent Claims of such Contributor to make, use, sell, offer for
        sale, have made, import, and otherwise transfer either its
        Contributions or its Contributor Version.

2.2. Effective Date

     The licenses granted in Section 2.1 with respect to any Contribution
     become effective for each Contribution on the date the Contributor first
     distributes such Contribution.

2.3. Limitations on Grant Scope

     The licenses granted in this Section 2 are the only rights granted under
     this License. No additional rights or licenses will be implied from the
     distribution or licensing of Covered Software under this License.
     Notwithstanding Section 2.1(b) above, no patent license is granted by a
     Contributor:

     a. for any code that a Contributor has removed from Covered Software; or

     b. for infringements caused by: (i) Your and any other third party's
        modifications of Covered Software, or (ii) the combination of its
        Contributions with other software (except as part of its Contributor
        Version); or

     c. under Patent Claims infringed by Covered Software in the absence of
        its Contributions.

     This License does not grant any rights in the trademarks, service marks,
     or logos of any Contributor (except as may be necessary to comply with
     the notice requirements in Section 3.4).

2.4. Subsequent Licenses

     No Contributor makes additional grants as a result of Your choice to
     distribute the Covered Software under a subsequent version of this
     License (see Section 10.2) or under the terms of a Secondary License (if
     permitted under the terms of Section 3.3).

2.5. Representation

     Each Contributor represents that the Contributor believes its
     Contributions are its original creation(s) or it has sufficient rights to
     grant the rights to its Contributions conveyed by this License.

2.6. Fair Use

     This License is not intended to limit any rights You have under
     applicable copyright doctrines of fair use, fair dealing, or other
     equivalents.

2.7. Conditions

     Sections 3.1, 3.2, 3.3, and 3.4 are conditions of the licenses granted in
     Section 2.1.


3. Responsibilities

3.1. Distribution of Source Form

     All distribution of Covered Software in Source Code Form, including any
     Modifications that You create or to which You contribute, must be under
     the terms of this License. You must inform recipients that the Source
     Code Form of the Covered Software is governed by the terms of this
     License, and how they can obtain a copy of this License. You may not
     attempt to alter or restrict the recipients' rights in the Source Code
     Form.

3.2. Distribution of Executable Form

     If You distribute Covered Software in Executable Form then:

     a. such Covered Software must also be made available in Source Code Form,
        as described in Section 3.1, and You must inform recipients of the
        Executable Form how they can obtain a copy of such Source Code Form by
        reasonable means in a timely manner, at a charge no more than the cost
        of distribution to the recipient; and

     b. You may distribute such Executable Form under the terms of this
        License, or sublicense it under different terms, provided that the
        license for the Executable Form does not attempt to limit or alter the
        recipients' rights in the Source Code Form under this License.

3.3. Distribution of a Larger Work

     You may create and distribute a Larger Work under terms of Your choice,
     provided that You also comply with the requirements of this License for
     the Covered Software. If the Larger Work is a combination of Covered
     Software with a work governed by one or more Secondary Licenses, and the
     Covered Software is not Incompatible With Secondary Licenses, this
     License permits You to additionally distribute such Covered Software
     under the terms of such Secondary License(s), so that the recipient of
     the Larger Work may, at their option, further distribute the Covered
     Software under the terms of either this License or such Secondary
     License(s).

3.4. Notices

     You may not remove or alter the substance of any license notices
     (including copyright notices, patent notices, disclaimers of warranty, or
     limitations of liability) contained within the Source Code Form of the
     Covered Software, except that You may alter any license notices to the
     extent required to remedy known factual inaccuracies.

3.5. Application of Additional Terms

     You may choose to offer, and to charge a fee for, warranty, support,
     indemnity or liability obligations to one or more recipients of Covered
     Software. However, You may do so only on Your own behalf, and not on
     behalf of any Contributor. You must make it absolutely clear that any
     such warranty, support, indemnity, or liability obligation is offered by
     You alone, and You hereby agree to indemnify every Contributor for any
     liability incurred by such Contributor as a result of warranty, support,
     indemnity or liability terms You offer. You may include additional
     disclaimers of warranty and limitations of liability specific to any
     jurisdiction.

4. Inability to Comply Due to Statute or Regulation

   If it is impossible for You to comply with any of the terms of this License
   with respect to some or all of the Covered Software due to statute,
   judicial order, or regulation then You must: (a) comply with the terms of
   this License to the maximum extent possible; and (b) describe the
   limitations and the code they affect. Such description must be placed in a
   text file included with all distributions of the Covered Software under
   this License. Except to the extent prohibited by statute or regulation,
   such description must be sufficiently detailed for a recipient of ordinary
   skill to be able to understand it.

5. Termination

5.1. The rights granted under this License will terminate automatically if You
     fail to comply with any of its terms. However, if You become compliant,
     then the rights granted under this License from a particular Contributor
     are reinstated (a) provisionally, unless and until such Contributor
     explicitly and finally terminates Your grants, and (b) on an ongoing
     basis, if such Contributor fails to notify You of the non-compliance by
     some reasonable means prior to 60 days after You have come back into
     compliance. Moreover, Your grants from a particular Contributor are
     reinstated on an ongoing basis if such Contributor notifies You of the
     non-compliance by some reasonable means, this is the first time You have
     received notice of non-compliance with this License from such
     Contributor, and You become compliant prior to 30 days after Your receipt
     of the notice.

5.2. If You initiate litigation against any entity by asserting a patent
     infringement claim (excluding declaratory judgment actions,
     counter-claims, and cross-claims) alleging that a Contributor Version
     directly or indirectly infringes any patent, then the rights granted to
     You by any and all Contributors for the Covered Software under Section
     2.1 of this License shall terminate.

5.3. In the event of termination under Sections 5.1 or 5.2 above, all end user
     license agreements (excluding distributors and resellers) which have been
     validly granted by You or Your distributors under this License prior to
     termination shall survive termination.

6. Disclaimer of Warranty

   Covered Software is provided under this License on an "as is" basis,
   without warranty of any kind, either expressed, implied, or statutory,
   including, without limitation, warranties that the Covered Software is free
   of defects, merchantable, fit for a particular purpose or non-infringing.
   The entire risk as to the quality and performance of the Covered Software
   is with You. Should any Covered Software prove defective in any respect,
   You (not any Contributor) assume the cost of any necessary servicing,
   repair, or correction. This disclaimer of warranty constitutes an essential
   part of this License. No use of  any Covered Software is authorized under
   this License except under this disclaimer.

7. Limitation of Liability

   Under no circumstances and under no legal theory, whether tort (including
   negligence), contract, or otherwise, shall any Contributor, or anyone who
   distributes Covered Software as permitted above, be liable to You for any
   direct, indirect, special, incidental, or consequential damages of any
   character including, without limitation, damages for lost profits, loss of
   goodwill, work stoppage, computer failure or malfunction, or any and all
   other commercial damages or losses, even if such party shall have been
   informed of the possibility of such damages. This limitation of liability
   shall not apply to liability for death or personal injury resulting from
   such party's negligence to the extent applicable law prohibits such
   limitation. Some jurisdictions do not allow the exclusion or limitation of
   incidental or consequential damages, so this exclusion and limitation may
   not apply to You.

8. Litigation

   Any litigation relating to this License may be brought only in the courts
   of a jurisdiction where the defendant maintains its principal place of
   business and such litigation shall be governed by laws of that
   jurisdiction, without reference to its conflict-of-law provisions. Nothing
   in this Section shall prevent a party's ability to bring cross-claims or
   counter-claims.

9. Miscellaneous

   This License represents the complete agreement concerning the subject
   matter hereof. If any provision of this License is held to be
   unenforceable, such provision shall be reformed only to the extent
   necessary to make it enforceable. Any law or regulation which provides that
   the language of a contract shall be construed against the drafter shall not
   be used to construe this License against a Contributor.


10. Versions of the License

10.1. New Versions

      Mozilla Foundation is the license steward. Except as provided in Section
      10.3, no one other than the license steward has the right to modify or
      publish new versions of this License. Each version will be given a
      distinguishing version number.

10.2. Effect of New Versions

      You may distribute the Covered Software under the terms of the version
      of the License under which You originally received the Covered Software,
      or under the terms of any subsequent version published by the license
      steward.

10.3. Modified Versions

      If you create software not governed by this License, and you want to
      create a new license for such software, you may create and use a
      modified version of this License if you rename the license and remove
      any references to the name of the license steward (except to note that
      such modified license differs from this License).

10.4. Distributing Source Code Form that is Incompatible With Secondary
      Licenses If You choose to distribute Source Code Form that is
      Incompatible With Secondary Licenses under the terms of this version of
      the License, the notice described in Exhibit B of this License must be
      attached.

Exhibit A - Source Code Form License Notice

      This Source Code Form is subject to the
      terms of the Mozilla Public License, v.
      2.0. If a copy of the MPL was not
      distributed with this file, You can
      obtain one at
      http://mozilla.org/MPL/2.0/.

If it is not possible or desirable to put the notice in a particular file,
then You may include the notice in a location (such as a LICENSE file in a
relevant directory) where a recipient would be likely to look for such a
notice.

You may add additional accurate notices of copyright ownership.

Exhibit B - "Incompatible With Secondary Licenses" Notice

      This Source Code Form is "Incompatible
      With Secondary Licenses", as defined by
      the Mozilla Public License, v. 2.0.
*/


type LogicalConn interface {
	net.Conn
	Cancel(*CancelData) error
}

type HelloData interface {
	hello()
}

type StartupData struct {
	Raw      *pgproto3.StartupMessage
	Database string
	Username string
	Password string // may be empty if RequirePassword is false
}

type CancelData struct {
	Raw *pgproto3.CancelRequest
}

func (*StartupData) hello() {}
func (*CancelData) hello()  {}

type SingleBackendProxy struct {
	Log             	zerolog.Logger
	RequirePassword 	bool
	FrontendTLS     	*tls.Config
	BackendTLS 			*tls.Config
	DialBackend     	func(context.Context, *StartupData) (LogicalConn, error)
	PasswordOverride	string

	gotBackend	chan struct{} // closed when first connection is received

	mu      sync.Mutex
	keyData map[pgproto3.BackendKeyData]LogicalConn
}

type DatabaseNotFoundError struct {
	Database string
}

func (e DatabaseNotFoundError) Error() string {
	return fmt.Sprintf("database %s not found", e.Database)
}

func (p *SingleBackendProxy) Serve(ctx context.Context, ln net.Listener) error {
	defer fns.CloseIgnore(ln)
	if p.gotBackend != nil {
		panic("SingleBackendProxy: Serve called twice")
	}
	p.gotBackend = make(chan struct{})

	go func() {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()

		select {
		case <-p.gotBackend:
		case <-ctx.Done():
			_ = ln.Close()
		}
	}()

	var tempDelay time.Duration // how long to sleep on accept failure
	gotBackend := false
	for {
		frontend, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("pgproxy: accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return fmt.Errorf("pgproxy: could not accept: %v", err)
		}

		if !gotBackend {
			close(p.gotBackend)
			gotBackend = true
		}

		go p.ProxyConn(ctx, frontend)
		tempDelay = 0
	}
}

func (p *SingleBackendProxy) ProxyConn(ctx context.Context, client net.Conn) {
	defer fns.CloseIgnore(client)

	cl, err := SetupClient(client, &ClientConfig{
		TLS:          p.FrontendTLS,
		WantPassword: p.RequirePassword,
	})
	if err != nil {
		p.Log.Error().Err(err).Msg("unable to setup frontend")
		return
	}

	switch data := cl.Hello.(type) {
	case *StartupData:
		if err := p.doRunProxy(ctx, cl); err != nil {
			p.Log.Error().Err(err).Msg("unable to run backend proxy")
		}
	case *CancelData:
		p.cancelRequest(ctx, data)
	default:
		p.Log.Error().Msgf("unknown hello message type: %T", data)
	}
}

func (p *SingleBackendProxy) doRunProxy(ctx context.Context, cl *Client) error {
	startup := cl.Hello.(*StartupData)
	server, err := p.DialBackend(ctx, startup)
	if err != nil {
		_ = cl.Backend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Message:  err.Error(),
		})
		return err
	}
	defer fns.CloseIgnore(server)

	fe, err := SetupServer(server, &ServerConfig{
		TLS: p.BackendTLS,
		Startup: startup,
	})

	if err != nil {
		log.Trace().Msg(err.Error())
		_ = cl.Backend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Message:  err.Error(),
		})
		return err
	}
	log.Trace().Msg("successfully setup server connection")

	err = AuthenticateClient(cl.Backend)
	if err != nil {
		log.Error().Err(err).Msg("unable to authenticate client")
		return err
	}
	log.Trace().Msg("successfully authenticated client")

	key, err := FinalizeInitialHandshake(cl.Backend, fe)
	if err != nil {
		log.Error().Err(err).Msg("unable to finalize handshake")
		return err
	}

	if key != nil {
		p.mu.Lock()
		if p.keyData == nil {
			p.keyData = make(map[pgproto3.BackendKeyData]LogicalConn)
		}
		p.keyData[*key] = server
		p.mu.Unlock()
	}

	err = CopySteadyState(cl.Backend, fe)
	if err != nil {
		log.Error().Err(err).Msg("unable to copy steady state")
		return err
	}

	return nil
}

type ServerConfig struct {
	TLS     *tls.Config // nil indicates no TLS
	Startup *StartupData
}

// SetupServer sets up a frontend connected to the given server.
func SetupServer(server net.Conn, cfg *ServerConfig) (*pgproto3.Frontend, error) {
	fe, err := serverTLSNegotiate(server, cfg.TLS)
	if err != nil {
		return nil, err
	}

	raw := cfg.Startup.Raw
	raw.Parameters["database"] = cfg.Startup.Database
	raw.Parameters["user"] = cfg.Startup.Username

	log.Trace().Msg("sending startup message to server")
	if err := fe.Send(raw); err != nil {
		return nil, fmt.Errorf("unable to send startup message: %v", err)
	}

	// Handle authentication
	for {
		msg, err := fe.Receive()
		if err != nil {
			return nil, fmt.Errorf("unexpected message from server: %v", err)
		}

		switch msg := msg.(type) {
		case *pgproto3.ErrorResponse:
			return nil, pgconn.ErrorResponseToPgError(msg)

		case pgproto3.AuthenticationResponseMessage:
			if len(cfg.Startup.Password) == 0 {
				if _, ok := msg.(*pgproto3.AuthenticationOk); !ok {
					return nil, fmt.Errorf("backend requested authentication but no password given")
				}
			}

			switch msg := msg.(type) {
			case *pgproto3.AuthenticationOk:
				// We're done!
				return fe, nil

			case *pgproto3.AuthenticationCleartextPassword:
				err := fe.Send(&pgproto3.PasswordMessage{Password: cfg.Startup.Password})
				if err != nil {
					return nil, err
				}

			case *pgproto3.AuthenticationMD5Password:
				password := computeMD5(cfg.Startup.Username, cfg.Startup.Password, msg.Salt)
				err := fe.Send(&pgproto3.PasswordMessage{Password: password})
				if err != nil {
					return nil, err
				}

			case *pgproto3.AuthenticationSASL:
				if err := scramAuth(fe, cfg.Startup.Password, msg.AuthMechanisms); err != nil {
					return nil, fmt.Errorf("authentication failed: %v", err)
				}

			default:
				return nil, fmt.Errorf("unsupported auth message: %T", msg)
			}

		default:
			return nil, fmt.Errorf("unexpected message type from backend: %T", msg)
		}
	}
}

func serverTLSNegotiate(server net.Conn, tlsConfig *tls.Config) (*pgproto3.Frontend, error) {
	cr := pgproto3.NewChunkReader(server)
	frontend := pgproto3.NewFrontend(cr, server)
	if tlsConfig == nil {
		return frontend, nil
	}

	log.Trace().Msg("negotiating tls with server")
	if err := frontend.Send(&pgproto3.SSLRequest{}); err != nil {
		return nil, err
	}
	// Read the TLS response.
	resp, err := cr.Next(1)
	if err != nil {
		return nil, err
	}
	log.Trace().Msg("received response: " + string(resp[0]))

	switch resp[0] {
	case 'S':
		log.Trace().Msg("server accepted tls request")
		tlsConn := tls.Client(server, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			log.Error().Err(err).Msg("server tls handshake failed")
			_ = tlsConn.Close()
			return nil, fmt.Errorf("server tls handshake failed: %v", err)
		}
		log.Trace().Msg("completed server tls handshake")

		// Return a new backend that wraps the tls conn.
		return pgproto3.NewFrontend(pgproto3.NewChunkReader(tlsConn), tlsConn), nil
	case 'N':
		log.Trace().Msg("server rejected tls request")
		return nil, fmt.Errorf("server rejected tls")
	case 'E':
		// ErrorMessage: we've already parsed the first byte so read it manually.
		hdr, err := cr.Next(4)
		if err != nil {
			return nil, err
		}
		if string(hdr) == "NCON" {
			errMessage := "NCON: Connection with PostgreSQL backend is inactive."
			return nil, fmt.Errorf(errMessage)	
		}
		bodyLen := int(binary.BigEndian.Uint32(hdr)) - 4
		msgBody, err := cr.Next(bodyLen)
		if err != nil {
			return nil, err
		}
		var errMsg pgproto3.ErrorResponse
		if err := errMsg.Decode(msgBody); err != nil {
			return nil, err
		}
		log.Error().Msgf("server tls negotiation error: %+v", errMsg)
		return nil, fmt.Errorf("could not negotiate tls with server: error %s: %s", errMsg.Code, errMsg.Message)
	default:
		return nil, fmt.Errorf("got unexpected response to tls request: %v", resp[0])
	}
}

type ClientConfig struct {
	// TLS, if non-nil, indicates we support TLS connections.
	TLS *tls.Config

	// WantPassword, if true, indicates we want to capture
	// the password sent by the frontend.
	WantPassword bool

	// Password, if not empty, sets the password override for the connection
	PasswordOverride string
}

type Client struct {
	Backend *pgproto3.Backend
	Hello   HelloData
}

// SetupClient sets up a backend connected to the given client.
// If tlsConfig is non-nil it negotiates TLS if requested by the client.
//
// On successful startup the returned message is either *pgproto3.StartupMessage or *pgproto3.CancelRequest.
//
// It is up to the caller to authenticate the client using AuthenticateClient.
func SetupClient(client net.Conn, cfg *ClientConfig) (*Client, error) {
	log.Trace().Msg("setting up client backend")
	be, msg, err := clientTLSNegotiate(client, cfg.TLS)
	if err != nil {
		return nil, err
	}

	if cancel, ok := msg.(*pgproto3.CancelRequest); ok {
		return &Client{
			Backend: be,
			Hello:   &CancelData{Raw: cancel},
		}, nil
	}

	startup := msg.(*pgproto3.StartupMessage)
	hello := &StartupData{
		Raw:      startup,
		Database: startup.Parameters["database"],
		Username: startup.Parameters["user"],
	}
	if cfg.WantPassword {
		err := be.Send(&pgproto3.AuthenticationCleartextPassword{})
		if err != nil {
			return nil, err
		}
		msg, err := be.Receive()
		if err != nil {
			return nil, err
		}
		passwd, ok := msg.(*pgproto3.PasswordMessage)
		if !ok {
			return nil, fmt.Errorf("expected PasswordMessage, got %T", msg)
		}
		hello.Password = passwd.Password
	}

	if cfg.PasswordOverride != "" {
		hello.Password = cfg.PasswordOverride
	}

	return &Client{
		Backend: be,
		Hello:   hello,
	}, nil
}

func clientTLSNegotiate(client net.Conn, tlsConfig *tls.Config) (*pgproto3.Backend, pgproto3.FrontendMessage, error) {
	log.Trace().Msg("negotiating TLS with client")
	backend := pgproto3.NewBackend(pgproto3.NewChunkReader(client), client)
	hasTLS := false

StartupMessageLoop:
	for {
		startup, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, err
		}
		switch startup := startup.(type) {
		case *pgproto3.SSLRequest:
			if hasTLS {
				return nil, nil, fmt.Errorf("received duplicate SSL request")
			} else if tlsConfig == nil {
				// We got an SSL request but we don't want to use TLS
				if _, err := client.Write([]byte{'N'}); err != nil {
					return nil, nil, err
				}
				continue StartupMessageLoop
			}

			if _, err := client.Write([]byte{'S'}); err != nil {
				return nil, nil, err
			}
			tlsConn := tls.Server(client, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				_ = tlsConn.Close()
				return nil, nil, fmt.Errorf("client tls handshake failed: %v", err)
			}
			log.Trace().Msg("client tls handshake successful")

			// The TLS handshake was successful.
			// Create a new backend that reads from the now-encrypted TLS connection.
			hasTLS = true
			backend = pgproto3.NewBackend(pgproto3.NewChunkReader(tlsConn), tlsConn)
		case *pgproto3.CancelRequest, *pgproto3.StartupMessage:
			// Startup complete.
			log.Debug().Msg("startup completed")
			return backend, startup, nil
		case *pgproto3.GSSEncRequest:
			// We got a GSSAPI encryption request but we don't support it.
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, nil, err
			}
			continue StartupMessageLoop
		}
	}
}

type AuthData struct {
	Username string
	Password string
}

// AuthenticateClient tells the client they've successfully authenticated.
func AuthenticateClient(be *pgproto3.Backend) error {
	_ = be.SetAuthType(pgproto3.AuthTypeOk)
	return be.Send(&pgproto3.AuthenticationOk{})
}

func computeMD5(username, password string, salt [4]byte) string {
	// concat('md5', md5(concat(md5(concat(password, username)), random-salt)))

	// s1 := md5(concat(password, username))
	// nosemgrep
	s1 := md5.Sum([]byte(password + username))
	// s2 := md5(concat(s1, random-salt))
	// nosemgrep
	s2 := md5.Sum([]byte(hex.EncodeToString(s1[:]) + string(salt[:])))
	return "md5" + hex.EncodeToString(s2[:])
}

func SendCancelRequest(conn io.ReadWriter, req *pgproto3.CancelRequest) error {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint32(buf[0:4], 16)
	binary.BigEndian.PutUint32(buf[4:8], 80877102)
	binary.BigEndian.PutUint32(buf[8:12], uint32(req.ProcessID))
	binary.BigEndian.PutUint32(buf[12:16], uint32(req.SecretKey))
	_, err := conn.Write(buf)
	if err != nil {
		return err
	}

	_, err = conn.Read(buf)
	if err != io.EOF {
		return err
	}
	return nil
}

// FinalizeInitialHandshake completes the handshake between client and server,
// snooping the BackendKeyData from the server if sent.
// It is nil if the server did not send any backend key data.
func FinalizeInitialHandshake(client *pgproto3.Backend, server *pgproto3.Frontend) (*pgproto3.BackendKeyData, error) {
	var keyData *pgproto3.BackendKeyData

	// Read messages from backend until we get ReadyForQuery
	for {
		msg, err := server.Receive()
		if err != nil {
			return nil, fmt.Errorf("pgproxy: cannot read from backend: %v", err)
		} else if err := client.Send(msg); err != nil {
			return nil, fmt.Errorf("pgproxy: could not write to frontend: %v", err)
		}

		switch msg := msg.(type) {
		case *pgproto3.BackendKeyData:
			// Make a copy; this object is only valid until the next call to Receive()
			copy := *msg
			keyData = &copy

		case *pgproto3.ReadyForQuery:
			// Handshake completed
			return keyData, nil
		}
	}
}

// CopySteadyState copies messages back and forth after the initial handshake.
func CopySteadyState(client *pgproto3.Backend, server *pgproto3.Frontend) error {
	done := make(chan struct{})
	defer close(done)

	go func() {
		// Copy from server to client.
		for {
			msg, err := server.Receive()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					select {
					case <-done:
						// The client terminated the connection so our connection
						// to the server is also being torn down; ignore the error.
						return
					default:
					}
				}

				log.Error().Err(err).Msg("pgproxy.CopySteadyState: failed to receive message from server")
				return
			}
			if err := client.Send(msg); err != nil {
				return
			}
		}
	}()

	// Copy from client to server.
	for {
		msg, err := client.Receive()
		if err != nil {
			log.Error().Err(err).Msg("pgproxy.CopySteadyState: failed to receive message from client")
			return err
		}
		err = server.Send(msg)
		if err != nil {
			return err
		}
		if _, ok := msg.(*pgproto3.Terminate); ok {
			log.Trace().Msg("received terminate from client, closing connection")
			return nil
		}
	}
}

func (p *SingleBackendProxy) cancelRequest(ctx context.Context, cancel *CancelData) {
	p.Log.Trace().Msg("received cancel request")
	key := pgproto3.BackendKeyData{
		ProcessID: cancel.Raw.ProcessID,
		SecretKey: cancel.Raw.SecretKey,
	}
	p.mu.Lock()
	conn, ok := p.keyData[key]
	p.mu.Unlock()

	if ok {
		if err := conn.Cancel(cancel); err != nil {
			p.Log.Error().Err(err).Msg("unable to send cancel request")
		}
	} else {
		p.Log.Error().Msg("could not find backend key data")
	}
}
