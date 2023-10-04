# Copyrights

* Copyright (c) 2023 Encore (www.encore.dev) - pgproxy.go
* Copyright (c) 2019-2021 Jack Christensen - scram.go

# pgproxy

pgproxy is a flexible proxy for the Postgres wire protocol that allows for customizing authentication and backend selection by breaking apart the startup message flow between frontend and backend.

Once authenticated, it falls back to being a dumb proxy
that simple shuffles bytes back and forth.
