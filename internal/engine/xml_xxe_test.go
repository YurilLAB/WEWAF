package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wewaf/internal/core"
)

func xmlBodyBlocked(eng *Engine, body string) bool {
	r := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/xml")
	tx := core.NewTransaction(nil, r, nil)
	tx.SetMetadata("body", []byte(body))
	return eng.ProcessRequestHeaders(tx) != nil || eng.ProcessRequestBody(tx) != nil
}

// TestXIncludeBlocked is the round-11 regression for the DOCTYPE-less XXE
// alternative. When an attacker controls only a sub-element of the XML (a SOAP
// body, a stored XML field) they cannot declare a DOCTYPE/ENTITY, so the
// entity rules never fire — but <xi:include href="..."/> still reads a local
// file or triggers an SSRF. The scheme/path-qualified hrefs get caught by the
// SSRF / traversal rules, but a bare relative href ("config.xml") slipped past
// until XXE-004 matched the XInclude namespace + element.
func TestXIncludeBlocked(t *testing.T) {
	eng := newFuzzEngine(t)
	attacks := []string{
		`<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="config.xml"/></r>`,
		`<xi:include href="secret"/>`,
		`<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="/etc/passwd" parse="text"/></r>`,
		`<data xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://169.254.169.254/latest/meta-data/"/></data>`,
		`<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="../../../../etc/passwd"/></r>`,
	}
	for _, p := range attacks {
		p := p
		t.Run(p, func(t *testing.T) {
			if !xmlBodyBlocked(eng, p) {
				t.Errorf("XInclude attack not blocked: %q", p)
			}
		})
	}
}

// TestXIncludeNoFalsePositive confirms XXE-004 does not collide with
// legitimate XML: XSLT's <xsl:include> lives in a different namespace, and
// ordinary SOAP / RSS / SVG carry neither the XInclude namespace nor element.
func TestXIncludeNoFalsePositive(t *testing.T) {
	eng := newFuzzEngine(t)
	legit := []string{
		`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="common.xsl"/></xsl:stylesheet>`,
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><getUser><id>42</id></getUser></soap:Body></soap:Envelope>`,
		`the xi:include feature lets you include files (described in prose)`,
	}
	for _, p := range legit {
		p := p
		t.Run(p, func(t *testing.T) {
			if xmlBodyBlocked(eng, p) {
				t.Errorf("legit XML wrongly blocked as XInclude: %q", p)
			}
		})
	}
}

// TestPHPOpenTagXMLProlog is the regression for the CRS-933100 carve-out. The
// rule must keep catching real PHP open tags while no longer flagging the XML
// declaration "<?xml ...?>" — otherwise every legitimate XML / SOAP / RSS /
// SVG / SAML request body is blocked as a PHP open tag (a pre-existing false
// positive; upstream OWASP CRS carves out the prolog the same way).
func TestPHPOpenTagXMLProlog(t *testing.T) {
	eng := newFuzzEngine(t)
	php := []string{
		`<?php system($_GET['c']); ?>`,
		`<?= $_GET['x'] ?>`,
		`<? echo shell_exec('id'); ?>`,
		`prefix<?php eval($_POST[0]);`,
	}
	for _, p := range php {
		p := p
		t.Run("php:"+p, func(t *testing.T) {
			if !rceBodyBlocked(eng, p) {
				t.Errorf("PHP open tag not blocked: %q", p)
			}
		})
	}
	xml := []string{
		`<?xml version="1.0" encoding="UTF-8"?><root><a>1</a></root>`,
		`<?xml version="1.0"?><rss version="2.0"><channel><title>n</title></channel></rss>`,
		`<?xml version='1.0' standalone='yes'?><doc/>`,
		`<?xml?>`,
		`<?xml/>`,
	}
	for _, p := range xml {
		p := p
		t.Run("xml:"+p, func(t *testing.T) {
			if rceBodyBlocked(eng, p) {
				t.Errorf("XML prolog wrongly blocked as PHP open tag: %q", p)
			}
		})
	}
}
