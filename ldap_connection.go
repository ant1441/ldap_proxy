package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"gopkg.in/ldap.v2"
)

type LdapConnection struct {
	Host string
	Port int
	TLS  bool

	BaseDN         string
	BindDN         string
	BindDNPassword string

	LdapScopeName string
}

func NewLdapConnection(host string, port int, tls bool,
	baseDN string, bindDN string, bindDNPassword string,
	scopeName string) *LdapConnection {
	log.Printf("Connecting to LDAP '%s:%d' (tls: %t)\n", host, port, tls)
	return &LdapConnection{
		Host:           host,
		Port:           port,
		BaseDN:         baseDN,
		BindDN:         bindDN,
		BindDNPassword: bindDNPassword,
		TLS:            tls,
		LdapScopeName:  scopeName,
	}
}

func (l *LdapConnection) VerifyUserPass(username string, password string) bool {
	ldap_con, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", l.Host, l.Port))
	if err != nil {
		log.Printf("Error connecting to LDAP Server '%s:%d': %s", l.Host, l.Port, err)
		return false
	}
	defer ldap_con.Close()

	if l.TLS {
		// Reconnect with TLS
		err = ldap_con.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Printf("Unable to connect to LDAP Server with TLS: %s", err)
			return false
		}
	}

	// First bind with a read only user
	err = ldap_con.Bind(l.BindDN, l.BindDNPassword)
	if err != nil {
		log.Printf("Error binding LDAP: %v", err)
		return false
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		l.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", username),
		[]string{"dn"},
		nil,
	)

	sr, err := ldap_con.Search(searchRequest)
	if err != nil {
		log.Printf("Error searching for '%s': %s", username, err)
		return false
	}

	if len(sr.Entries) != 1 {
		log.Printf("User does not exist or too many entries returned")
		return false
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = ldap_con.Bind(userdn, password)
	if err != nil {
		log.Printf("Error binding as user: %s", err)
		return false
	}

	return true
}
