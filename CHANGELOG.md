0.5.0 (2021-02-08)
==================
* Fix support for ldap_scope_name

0.4.0 (2018-11-23)
==================
* URGENT SECURITY FIX: authentication bypass via LDAP passwordless auth LDAP permits passwordless Bind operations by clients - this application verified authentication without checking specifically for an empty password, thus allowing authentication as any valid user by leaving the password field blank. This issue has been present since the first release of this application.

  See also:
  * https://github.com/go-ldap/ldap/pull/126
  * https://github.com/pinepain/ldap-auth-proxy/issues/8
  * https://github.com/go-ldap/ldap/issues/93

* Added HTTP security headers and prevent caching of proxy pages

0.3.4 (2018-10-29)
==================
* Make LDAP group comparisons case-insensitive

0.3.3 (2018-06-21)
==================
* Refactor LDAP connection code and use connections more efficiently

0.3.2 (2018-06-19)
==================
* Fix issue with LDAP timeouts when old connections are re-used

0.3.1 (2018-06-13)
==================
* Fix redirect behaviour after login

0.3.0 (2018-06-08)
==================
* Add the ability to restrict access by LDAP group

0.2.0 (2018-01-25)
==================
* Add options for customizing TLS cipher suites

0.1.1 (2017-11-13)
==================
* Disabled autocomplete on the login form

0.1.0 (2017-09-18)
==================
Initial release
