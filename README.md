ldap_proxy
=================

A reverse proxy and static file server that provides authentication using LDAP.

Strongly inspired by [bitly/oauth2_proxy](https://github.com/bitly/oauth2_proxy).

[![Build Status](https://secure.travis-ci.org/ant1441/ldap_proxy.png?branch=master)](http://travis-ci.org/ant1441/ldap_proxy)


## Installation

1. Download [Prebuilt Binary](https://github.com/skybet/ldap_proxy/releases) (current release is `v2.2`) or build with `$ go get github.com/skybet/ldap_proxy` which will put the binary in `$GOROOT/bin`
3. Configure Ldap Proxy using config file, command line options, or environment variables
4. Configure SSL or Deploy behind a SSL endpoint (example provided for Nginx)

## LDAP Configuration

* `-ldap-server-host <hostname>`
* `-ldap-server-port <port>`
* `-ldap-tls[=false]`
* `-ldap-scope-name <name>`
* `-ldap-base-dn <dn>`
* `-ldap-bind-dn <dn>`
* `-ldap-bind-dn-password <password>`
* `-ldap-groups [optional list of acceptable groups]`

## Configuration

`ldap_proxy` can be configured via [config file](#config-file), [command line options](#command-line-options) or [environment variables](#environment-variables).

To generate a strong cookie secret use `python -c 'import os,base64; print base64.b64encode(os.urandom(16))'`

### Config File

An example [ldap_proxy.cfg](contrib/ldap_proxy.cfg.example) config file is in the contrib directory. It can be used by specifying `-config=/etc/ldap_proxy.cfg`

### Command Line Options

```
Usage of ldap_proxy:
  -config string: path to config file

  -http-address string: [http://]<addr>:<port> or unix://<path> to listen on for HTTP clients (default "127.0.0.1:4180")
  -https-address string: <addr>:<port> to listen on for HTTPS clients (default ":443")
  -tls-cert string: path to certificate file
  -tls-key string: path to private key file

  -upstream value: the http url(s) of the upstream endpoint or file:// paths for static files. Routing is based on the path
  -request-logging: Log requests to stdout (default true)

  -ldap-server-host: the hostname of the LDAP server
  -ldap-sever-port: the port of the LDAP server (default: 389)
  -ldap-tls: use TLS when speaking to the LDAP host
  -ldap-scope-name: name of LDAP scope (default: LDAP)
  -ldap-base-dn: base DN to search in LDAP
  -ldap-bind-dn: base DN to bind LDAP
  -ldap-bind-dn-password: password for LDAP bind
  -ldap-groups: optional list of LDAP groups the user should be in (default: any)

  -pass-basic-auth: pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream (default true)
  -pass-user-headers: pass X-Forwarded-User and X-Forwarded-Email information to upstream (default true)
  -basic-auth-password string: the password to set when passing the HTTP Basic Auth header
  -pass-host-header: pass the request Host Header to upstream (default true)

  -skip-auth-preflight: will skip authentication for OPTIONS requests
  -skip-auth-regex value: bypass authentication for requests paths that match (may be given multiple times)
  -skip-auth-ips value: bypass authentication for requests hosts that match (may be given multiple times)

  -ssl-insecure-skip-verify: skip validation of certificates presented when using HTTPS (default false)
  -real-ip-header: The header which specifies the real IP of the request. Caution: This header may allow a malicious actor to spoof an internal IP, bypassing whitelists. Set to the empty string to ignore (default X-Real-IP)
  -proxy-ip-header: The header which specifies the real IP of the proxied request. Caution: This header may allow a malicious actor to spoof an internal IP, bypassing whitelists. Set to the empty string to ignore (default X-Forwarded-For)

  -email-domain value: authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email
  -authenticated-emails-file string: authenticate against emails via file (one per line)
  -htpasswd-file string: additionally authenticate against a htpasswd file. Entries must be created with "htpasswd -s" for SHA encryption
  -custom-templates-dir string: path to custom html templates
  -footer string: custom footer string. Use "-" to disable default footer.
  -proxy-prefix string: the url root path that this proxy should be nested under (e.g. /<ldap_proxy>/sign_in) (default "/ldap_auth")

  -cookie-name string: the name of the cookie that the ldap_proxy creates (default "_ldap_proxy")
  -cookie-secret string: the seed string for secure cookies (optionally base64 encoded)
  -cookie-domain string: an optional cookie domain to force cookies to (ie: .yourcompany.com)*
  -cookie-expire duration: expire timeframe for cookie (default 168h0m0s)
  -cookie-refresh duration: refresh the cookie after this duration; 0 to disable
  -cookie-secure: set secure (HTTPS) cookie flag (default true)
  -cookie-httponly: set HttpOnly cookie flag (default true)

  -login-url string: Authentication endpoint

  -set-xauthrequest: set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)
  -signature-key string: LAP-Signature request signature key (algorithm:secretkey)

  -version: print version string
```

### Upstreams Configuration

`ldap_proxy` supports having multiple upstreams, and has the option to pass requests on to HTTP(S) servers or serve static files from the file system. HTTP and HTTPS upstreams are configured by providing a URL such as `http://127.0.0.1:8080/` for the upstream parameter, that will forward all authenticated requests to be forwarded to the upstream server. If you instead provide `http://127.0.0.1:8080/some/path/` then it will only be requests that start with `/some/path/` which are forwarded to the upstream.

Static file paths are configured as a file:// URL. `file:///var/www/static/` will serve the files from that directory at `http://[ldap_proxy url]/var/www/static/`, which may not be what you want. You can provide the path to where the files should be available by adding a fragment to the configured URL. The value of the fragment will then be used to specify which path the files are available at. `file:///var/www/static/#/static/` will ie. make `/var/www/static/` available at `http://[ldap_proxy url]/static/`.

Multiple upstreams can either be configured by supplying a comma separated list to the `-upstream` parameter, supplying the parameter multiple times or provinding a list in the [config file](#config-file). When multiple upstreams are used routing to them will be based on the path they are set up with.

### Environment variables

The following environment variables can be used in place of the corresponding command-line arguments:

- `LDAP_PROXY_COOKIE_NAME`
- `LDAP_PROXY_COOKIE_SECRET`
- `LDAP_PROXY_COOKIE_DOMAIN`
- `LDAP_PROXY_COOKIE_EXPIRE`
- `LDAP_PROXY_COOKIE_REFRESH`

## SSL Configuration

There are two recommended configurations.

1) Configure SSL Terminiation with LDAP Proxy by providing a `--tls-cert=/path/to/cert.pem` and `--tls-key=/path/to/cert.key`.

The command line to run `ldap_proxy` in this configuration would look like this:

```bash
./ldap_proxy \
   --email-domain="yourcompany.com"  \
   --upstream=http://127.0.0.1:8080/ \
   --tls-cert=/path/to/cert.pem \
   --tls-key=/path/to/cert.key \
   --cookie-secret=... \
   --cookie-secure=true \
   -ldap-server-host ldap.internal \
   -ldap-base-dn 'dc=example,dc=org' \
   -ldap-bind-dn 'cn=admin,dc=example,dc=org' \
   -ldap-bind-dn-password admin
```


2) Configure SSL Termination with [Nginx](http://nginx.org/) (example config below), Amazon ELB, Google Cloud Platform Load Balancing, or ....

Because `ldap_proxy` listens on `127.0.0.1:4180` by default, to listen on all interfaces (needed when using an
external load balancer like Amazon ELB or Google Platform Load Balancing) use `--http-address="0.0.0.0:4180"` or
`--http-address="http://:4180"`.

Nginx will listen on port `443` and handle SSL connections while proxying to `ldap_proxy` on port `4180`.
`ldap_proxy` will then authenticate requests for an upstream application. The external endpoint for this example
would be `https://internal.yourcompany.com/`.

An example Nginx config follows. Note the use of `Strict-Transport-Security` header to pin requests to SSL
via [HSTS](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security):

```
server {
    listen 443 default ssl;
    server_name internal.yourcompany.com;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/cert.key;
    add_header Strict-Transport-Security max-age=2592000;

    location / {
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_connect_timeout 1;
        proxy_send_timeout 30;
        proxy_read_timeout 30;
    }
}
```

The command line to run `ldap_proxy` in this configuration would look like this:

```bash
./ldap_proxy \
   --upstream=http://127.0.0.1:8080/ \
   --cookie-secret=... \
   --cookie-secure=true \
   -ldap-server-host ldap.internal \
   -ldap-base-dn 'dc=example,dc=org' \
   -ldap-bind-dn 'cn=admin,dc=example,dc=org' \
   -ldap-bind-dn-password admin
```

## Endpoint Documentation

LDAP Proxy responds directly to the following endpoints. All other endpoints will be proxied upstream when authenticated. The `/ldap_auth` prefix can be changed with the `--proxy-prefix` config variable.

* /robots.txt - returns a 200 OK response that disallows all User-agents from all paths; see [robotstxt.org](http://www.robotstxt.org/) for more info
* /ping - returns an 200 OK response
* /ldap_auth/sign_in - the login page, which also doubles as a sign out page (it clears cookies)
* /ldap_auth/auth - only returns a 202 Accepted response or a 401 Unauthorized response; for use with the [Nginx `auth_request` directive](#nginx-auth-request)

## Request signatures

If `signature_key` is defined, proxied requests will be signed with the
`LAP-Signature` header, which is a [Hash-based Message Authentication Code
(HMAC)](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
of selected request information and the request body [see `SIGNATURE_HEADERS`
in `ldapproxy.go`](./ldapproxy.go).

`signature_key` must be of the form `algorithm:secretkey`, (ie: `signature_key = "sha1:secret0"`)

For more information about HMAC request signature validation, read the
following:

* [Amazon Web Services: Signing and Authenticating REST
  Requests](https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html)
* [rc3.org: Using HMAC to authenticate Web service
  requests](http://rc3.org/2011/12/02/using-hmac-to-authenticate-web-service-requests/)

## Logging Format

LDAP Proxy logs requests to stdout in a format similar to Apache Combined Log.

```
<REMOTE_ADDRESS> - <user@domain.com> [19/Mar/2015:17:20:19 -0400] <HOST_HEADER> GET <UPSTREAM_HOST> "/path/" HTTP/1.1 "<USER_AGENT>" <RESPONSE_CODE> <RESPONSE_BYTES> <REQUEST_DURATION>
```

## <a name="nginx-auth-request"></a>Configuring for use with the Nginx `auth_request` directive

The [Nginx `auth_request` directive](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) allows Nginx to authenticate requests via the ldap_proxy's `/auth` endpoint, which only returns a 202 Accepted response or a 401 Unauthorized response without proxying the request through. For example:

```nginx
server {
  listen 443 ssl;
  server_name ...;
  include ssl/ssl.conf;

  location /ldap_auth/ {
    proxy_pass       http://127.0.0.1:4180;
    proxy_set_header Host                    $host;
    proxy_set_header X-Real-IP               $remote_addr;
    proxy_set_header X-Scheme                $scheme;
    proxy_set_header X-Auth-Request-Redirect $request_uri;
  }

  location / {
    auth_request /ldap_auth/auth;
    error_page 401 = /ldap_auth/sign_in;

    # pass information via X-User and X-Email headers to backend,
    # requires running with --set-xauthrequest flag
    auth_request_set $user   $upstream_http_x_auth_request_user;
    auth_request_set $email  $upstream_http_x_auth_request_email;
    proxy_set_header X-User  $user;
    proxy_set_header X-Email $email;

    # if you enabled --cookie-refresh, this is needed for it to work with auth_request
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie;

    proxy_pass http://backend/;
    # or "root /path/to/site;" or "fastcgi_pass ..." etc
  }
}
```
