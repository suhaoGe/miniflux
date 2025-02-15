// SPDX-FileCopyrightText: Copyright The Miniflux Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package scraper // import "miniflux.app/v2/reader/scraper"

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"miniflux.app/v2/config"
	"miniflux.app/v2/http/client"
	"miniflux.app/v2/logger"
	"miniflux.app/v2/reader/readability"
	"miniflux.app/v2/url"

	"github.com/PuerkitoBio/goquery"
)

// Fetch downloads a web page and returns relevant contents.
func Fetch(websiteURL, rules, userAgent string, cookie string, allowSelfSignedCertificates, useProxy bool) (string, error) {
	clt := client.NewClientWithConfig(websiteURL, config.Opts)
	clt.WithUserAgent(userAgent)
	clt.WithCookie(cookie)
	if useProxy {
		clt.WithProxy()
	}
	clt.AllowSelfSignedCertificates = allowSelfSignedCertificates

	response, err := clt.Get()
	if err != nil {
		return "", err
	}

	if response.HasServerFailure() {
		return "", errors.New("scraper: unable to download web page")
	}

	if !isAllowedContentType(response.ContentType) {
		return "", fmt.Errorf("scraper: this resource is not a HTML document (%s)", response.ContentType)
	}

	if err = response.EnsureUnicodeBody(); err != nil {
		return "", err
	}

	// The entry URL could redirect somewhere else.
	sameSite := url.Domain(websiteURL) == url.Domain(response.EffectiveURL)
	websiteURL = response.EffectiveURL

	if rules == "" {
		rules = getPredefinedScraperRules(websiteURL)
	}

	var content string
	if sameSite && rules != "" {
		logger.Debug(`[Scraper] Using rules %q for %q`, rules, websiteURL)
		content, err = scrapContent(response.Body, rules)
	} else {
		logger.Debug(`[Scraper] Using readability for %q`, websiteURL)
		content, err = readability.ExtractContent(response.Body)
	}

	if err != nil {
		return "", err
	}

	return content, nil
}

func scrapContent(page io.Reader, rules string) (string, error) {
	document, err := goquery.NewDocumentFromReader(page)
	if err != nil {
		return "", err
	}

	contents := ""
	document.Find(rules).Each(func(i int, s *goquery.Selection) {
		var content string

		content, _ = goquery.OuterHtml(s)
		contents += content
	})

	return contents, nil
}

func getPredefinedScraperRules(websiteURL string) string {
	urlDomain := url.Domain(websiteURL)

	for domain, rules := range predefinedRules {
		if strings.Contains(urlDomain, domain) {
			return rules
		}
	}

	return ""
}

func isAllowedContentType(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.HasPrefix(contentType, "text/html") ||
		strings.HasPrefix(contentType, "application/xhtml+xml")
}
