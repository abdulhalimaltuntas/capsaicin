package reporting

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/abdulhalimaltuntas/capsaicin/internal/scanner"
)

// SaveBurp writes discovered endpoints as a Burp Suite sitemap XML that can be
// imported via Target → Site map → "Load". Because Capsaicin does not retain raw
// request/response bytes, each item carries a synthesized request line and a
// minimal status-line response — enough to populate Burp's site map and scope.
func SaveBurp(results []scanner.Result, filename string) error {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	SortResults(sorted)

	file, err := createOutput(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\n")
	b.WriteString(`<items burpVersion="capsaicin">` + "\n")

	for i := range sorted {
		writeBurpItem(&b, &sorted[i])
	}
	b.WriteString("</items>\n")

	_, err = io.WriteString(file, b.String())
	return err
}

// writeBurpItem serializes one result as a Burp <item>.
func writeBurpItem(b *strings.Builder, r *scanner.Result) {
	// The URL may carry a "[BYPASS...]"/"[VHOST...]" annotation appended by the
	// scanner — strip it back to a plain URL for parsing.
	clean := r.URL
	if idx := strings.Index(clean, " ["); idx >= 0 {
		clean = clean[:idx]
	}
	u, err := url.Parse(clean)
	if err != nil || u.Host == "" {
		return
	}

	protocol := u.Scheme
	if protocol == "" {
		protocol = "http"
	}
	port := u.Port()
	if port == "" {
		if protocol == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	method := r.Method
	if method == "" || strings.Contains(method, "+") {
		method = "GET"
	}

	rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		method, path, u.Host, r.UserAgent)
	rawResp := fmt.Sprintf("HTTP/1.1 %d\r\nServer: %s\r\nContent-Length: %d\r\n\r\n",
		r.StatusCode, r.Server, r.Size)

	ext := ""
	if dot := strings.LastIndex(path, "."); dot >= 0 && !strings.Contains(path[dot:], "/") {
		ext = strings.TrimPrefix(path[dot:], ".")
		if q := strings.IndexAny(ext, "?#"); q >= 0 {
			ext = ext[:q]
		}
	}

	fmt.Fprintf(b, "  <item>\n")
	fmt.Fprintf(b, "    <url><![CDATA[%s]]></url>\n", clean)
	fmt.Fprintf(b, "    <host>%s</host>\n", u.Hostname())
	fmt.Fprintf(b, "    <port>%s</port>\n", port)
	fmt.Fprintf(b, "    <protocol>%s</protocol>\n", protocol)
	fmt.Fprintf(b, "    <method><![CDATA[%s]]></method>\n", method)
	fmt.Fprintf(b, "    <path><![CDATA[%s]]></path>\n", path)
	fmt.Fprintf(b, "    <extension>%s</extension>\n", ext)
	fmt.Fprintf(b, "    <request base64=\"true\"><![CDATA[%s]]></request>\n", base64.StdEncoding.EncodeToString([]byte(rawReq)))
	fmt.Fprintf(b, "    <status>%d</status>\n", r.StatusCode)
	fmt.Fprintf(b, "    <responselength>%d</responselength>\n", r.Size)
	fmt.Fprintf(b, "    <response base64=\"true\"><![CDATA[%s]]></response>\n", base64.StdEncoding.EncodeToString([]byte(rawResp)))
	fmt.Fprintf(b, "    <comment><![CDATA[severity=%s tags=%s]]></comment>\n", r.Severity, strings.Join(r.Tags, ","))
	fmt.Fprintf(b, "  </item>\n")
}
