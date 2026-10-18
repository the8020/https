# HTTPS and certificate authentication

Open **HTTPS** in the system to edit allowed domains, Let's Encrypt settings,
enrollment limits, and server certificates. New systems enable HTTPS and Let's
Encrypt with `*` allowed. Public issuance needs working DNS and a reachable
HTTP-01 challenge endpoint on port 80. Local names use the system's local CA;
its public certificate is available under **Advanced → Local authority**.

An allowed-domain entry can be an exact hostname, `*`, or `*.example.com`. The
last form permits one additional label, excluding the apex and deeper
descendants. These patterns control admission; automatic issuance requests
concrete names. Uploaded wildcard certificates are supported.

The default enrollment limits are two new hostname attempts per hour, ten
admitted hostnames, two concurrent checks, and a three-second check timeout.
These limits are shared across nodes. Failed attempts consume the allowance;
zero enrollment limits pause new names while existing certificates can renew.

Upload a PEM server certificate with its intermediate chain and matching PEM
private key. Replacement applies to new TLS connections while existing work
continues. **Advanced → Node diagnostics** shows each node's desired and applied
revision or unavailable status. Nodes load shared database state; an offline
node catches up when it returns. Backups require the original system master key
to recover encrypted private keys.

## Calling a service with a user certificate

Register the client's public X.509 certificate, in PEM or DER form, under
**Users** or **My account**. Keep its private key on the client. Each enrolled
certificate belongs to one user; a reissued certificate needs new enrollment.
Enabled accounts can use certificates without a password.

```sh
curl --cert client.crt --key client.key \
  https://app.example.com/the8020/example/service/
```

Replace the URL with the service's canonical path. TLS proves possession of the
private key; the client adds no certificate HTTP header. Removing enrollment or
disabling the user affects subsequent requests, including on existing TLS
connections.

## Behind a load balancer

TCP passthrough preserves the original TLS connection and needs no certificate
forwarding headers. With external TLS termination, ordinary HTTP forwarding
continues to support passwords and platform tokens.

For client-certificate authentication after external termination, configure the
terminator to obtain the actual client certificate and verify possession of its
private key during TLS. It must replace incoming certificate headers and send
the leaf certificate using
[RFC 9440 `Client-Cert`](https://www.rfc-editor.org/rfc/rfc9440.html), encoded
as `Client-Cert: :BASE64_DER:`. Clear certificate headers when no client
certificate was presented. Configure the terminator's immediate backend IP or
CIDR under **Advanced → Trusted certificate proxies**, and protect the backend
path so only those terminators can assert certificate evidence. Forwarded
certificate authentication is disabled until configured.

See [AGENTS.md](AGENTS.md) for ownership and verification commands.
