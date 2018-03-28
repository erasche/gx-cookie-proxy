package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	_ "github.com/lib/pq"
	cache "github.com/patrickmn/go-cache"
	"golang.org/x/crypto/blowfish"
)

func timedLookupEmailByCookie(b *ProxyHandler, cookie string) (string, bool) {
	start := time.Now()
	email, found := lookupEmailByCookie(b, cookie)
	t := time.Now()
	elapsed := t.Sub(start)
	metric_time("query_timing", elapsed)

	return email, found
}

func cookieToSessionKey(b *ProxyHandler, cookie string) (sessionKey string) {
	data, err := hex.DecodeString(cookie[14:])
	// If we can decode, exit early.
	if err != nil {
		return "will-never-match"
	}

	// Decrypt the session key
	pt := make([]byte, 40)
	for i := 0; i < len(data); i += blowfish.BlockSize {
		j := i + blowfish.BlockSize
		b.GalaxyCipher.Decrypt(pt[i:j], data[i:j])
	}

	// And strip all the exclamations from it.
	session_key := strings.Replace(string(pt), "!", "", -1)
	safe_session_key := hexReg.ReplaceAllString(session_key, "")

	// Debugging
	log.WithFields(log.Fields{
		"sk": safe_session_key,
	}).Debug("Session Key Decoded")
	return safe_session_key
}

func lookupEmailByCookie(b *ProxyHandler, cookie string) (email string, found bool) {
	cachedEmail, found := b.Cache.Get(cookie[14:])
	log.WithFields(log.Fields{
		"hit": found,
	}).Debug("Cache hit")
	if found {
		metric_incr("cache.hit")
		return cachedEmail.(string), found
	}
	metric_incr("cache.miss")

	safe_session_key := cookieToSessionKey(b, cookie)
	err := b.GalaxyDB.QueryRow(b.QueryString, safe_session_key).Scan(&email)

	if err != nil {
		if fmt.Sprintf("%s", err) == "sql: no rows in result set" {
			log.Info("Invalid session key / cookie")
		} else {
			log.Error(err)
		}
		return "", false
	}
	log.WithFields(log.Fields{
		"email": email,
	}).Debug("Invalid session key / cookie")

	b.Cache.Set(cookie[14:], email, cache.DefaultExpiration)
	return email, false
}
