package reporting

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/abdulhalimaltuntas/capsaicin/internal/scanner"
)

// GenerateHTML renders an interactive standalone report: stat cards, severity
// filter pills, live search, and click-to-sort columns — all dependency-free
// vanilla JS. Every value derived from the target is HTML-escaped.
func GenerateHTML(results []scanner.Result, filename string) error {
	sorted := make([]scanner.Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		if CompareSeverityStr(sorted[i].Severity, sorted[j].Severity) != 0 {
			return CompareSeverityStr(sorted[i].Severity, sorted[j].Severity) > 0
		}
		return sorted[i].URL < sorted[j].URL
	})

	sev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	var count2xx, count3xx, countSecrets, countWAF int
	for i := range sorted {
		r := &sorted[i]
		if _, ok := sev[r.Severity]; ok {
			sev[r.Severity]++
		}
		switch {
		case r.StatusCode >= 200 && r.StatusCode < 300:
			count2xx++
		case r.StatusCode >= 300 && r.StatusCode < 400:
			count3xx++
		}
		if r.SecretFound {
			countSecrets++
		}
		if r.WAFDetected != "" {
			countWAF++
		}
	}

	var b strings.Builder
	b.WriteString(htmlHead)

	// Header + stat cards.
	fmt.Fprintf(&b, `<div class="meta">Generated %s · %d findings</div>`, html.EscapeString(time.Now().Format("2006-01-02 15:04:05")), len(sorted))
	b.WriteString(`<div class="stats">`)
	statCard(&b, "Critical", sev["critical"], "sev-critical")
	statCard(&b, "High", sev["high"], "sev-high")
	statCard(&b, "Medium", sev["medium"], "sev-medium")
	statCard(&b, "Success 2xx", count2xx, "")
	statCard(&b, "Secrets", countSecrets, "sev-secret")
	statCard(&b, "WAF", countWAF, "")
	b.WriteString(`</div>`)

	// Filter pills.
	b.WriteString(`<div class="pills">`)
	pill(&b, "all", "All", len(sorted))
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if sev[s] > 0 {
			pill(&b, s, strings.Title(s), sev[s])
		}
	}
	b.WriteString(`</div>`)

	b.WriteString(`<input type="text" id="q" placeholder="Search findings…">`)
	b.WriteString(`<table id="t"><thead><tr>`)
	for _, h := range []string{"Severity", "Status", "URL", "Size", "Details"} {
		fmt.Fprintf(&b, `<th onclick="sortBy(this)">%s</th>`, h)
	}
	b.WriteString(`</tr></thead><tbody>`)

	for i := range sorted {
		r := &sorted[i]
		details := detailBadges(r)
		fmt.Fprintf(&b, `<tr data-sev="%s"><td><span class="badge sev-%s">%s</span></td>`+
			`<td class="st-%d">%d</td><td><code>%s</code></td><td data-n="%d">%s</td><td>%s</td></tr>`,
			html.EscapeString(r.Severity), html.EscapeString(r.Severity), html.EscapeString(strings.ToUpper(r.Severity)),
			r.StatusCode/100, r.StatusCode, html.EscapeString(r.URL), r.Size, formatBytes(r.Size), details)
	}

	b.WriteString(`</tbody></table>`)
	b.WriteString(htmlScript)
	b.WriteString(`</div></body></html>`)

	f, err := createOutput(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte(b.String()))
	return err
}

func statCard(b *strings.Builder, label string, n int, class string) {
	fmt.Fprintf(b, `<div class="card"><div class="v %s">%d</div><div class="l">%s</div></div>`, class, n, label)
}

func pill(b *strings.Builder, sev, label string, n int) {
	fmt.Fprintf(b, `<button class="pill" data-f="%s" onclick="filt(this)">%s <span>%d</span></button>`, sev, label, n)
}

func detailBadges(r *scanner.Result) string {
	var parts []string
	if r.SecretFound && len(r.SecretTypes) > 0 {
		parts = append(parts, `<span class="tag tag-secret">🔑 `+html.EscapeString(strings.Join(r.SecretTypes, ", "))+`</span>`)
	}
	if r.WAFDetected != "" {
		parts = append(parts, `<span class="tag tag-waf">🛡 `+html.EscapeString(r.WAFDetected)+`</span>`)
	}
	for _, t := range r.Tags {
		if t == "secret" || t == "waf" {
			continue
		}
		parts = append(parts, `<span class="tag">`+html.EscapeString(t)+`</span>`)
	}
	tech := []string{}
	if r.Server != "" {
		tech = append(tech, r.Server)
	}
	if r.PoweredBy != "" {
		tech = append(tech, r.PoweredBy)
	}
	if len(tech) > 0 {
		parts = append(parts, `<code class="tech">`+html.EscapeString(strings.Join(tech, ", "))+`</code>`)
	}
	return strings.Join(parts, " ")
}

func formatBytes(n int) string {
	switch {
	case n >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(n)/1024/1024)
	case n >= 1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// CompareSeverityStr ranks severities (higher = more severe) for sorting.
func CompareSeverityStr(a, b string) int {
	rank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	return rank[a] - rank[b]
}

const htmlHead = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Capsaicin Scan Report</title><style>
:root{--bg:#0f1115;--card:#181b22;--fg:#e6e6e6;--mut:#8a90a0;--line:#262a33;--acc:#ff5a1f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1400px;margin:0 auto;padding:28px}
h1{font-size:22px;margin:0 0 4px}h1 span{color:var(--acc)}
.meta{color:var(--mut);margin-bottom:22px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .v{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px;margin-top:2px}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.pill{background:var(--card);border:1px solid var(--line);color:var(--fg);border-radius:999px;padding:6px 12px;cursor:pointer;font-size:13px}
.pill.on{border-color:var(--acc);color:var(--acc)}.pill span{color:var(--mut)}
#q{width:100%;padding:11px 14px;background:var(--card);border:1px solid var(--line);border-radius:8px;color:var(--fg);margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px;border-bottom:2px solid var(--line);color:var(--mut);cursor:pointer;user-select:none;position:sticky;top:0;background:var(--bg)}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:hover td{background:#1c2029}
code{background:#12151b;border:1px solid var(--line);padding:2px 6px;border-radius:5px;font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
.tech{color:var(--mut)}
.st-2{color:#3fb950;font-weight:600}.st-3{color:#58a6ff;font-weight:600}.st-4{color:#f85149;font-weight:600}.st-5{color:#d29922;font-weight:600}
.badge{display:inline-block;padding:2px 8px;border-radius:5px;font-size:11px;font-weight:700}
.sev-critical{color:#ff6b6b}.sev-high{color:#ff9f43}.sev-medium{color:#feca57}.sev-low{color:#54a0ff}.sev-info{color:#8a90a0}.sev-secret{color:#feca57}
.badge.sev-critical{background:#3a1418;color:#ff6b6b}.badge.sev-high{background:#3a2410;color:#ff9f43}.badge.sev-medium{background:#3a3410;color:#feca57}.badge.sev-low{background:#122840;color:#54a0ff}.badge.sev-info{background:#20242d;color:#8a90a0}
.tag{display:inline-block;padding:2px 7px;border-radius:5px;font-size:11px;background:#20242d;color:var(--mut);border:1px solid var(--line)}
.tag-secret{background:#3a3410;color:#feca57;border-color:#5a5220}.tag-waf{background:#241a3a;color:#b48cff;border-color:#3a2c5a}
</style></head><body><div class="wrap"><h1>🌶 <span>Capsaicin</span> Scan Report</h1>`

const htmlScript = `<script>
var q=document.getElementById('q'),rows=[].slice.call(document.querySelectorAll('#t tbody tr')),curF='all';
function apply(){var s=q.value.toLowerCase();rows.forEach(function(r){var okF=curF==='all'||r.dataset.sev===curF;var okS=!s||r.textContent.toLowerCase().indexOf(s)>=0;r.style.display=(okF&&okS)?'':'none';});}
function filt(btn){curF=btn.dataset.f;document.querySelectorAll('.pill').forEach(function(p){p.classList.remove('on')});btn.classList.add('on');apply();}
q.addEventListener('input',apply);
var dir=1,lastCol=-1;
function sortBy(th){var idx=[].indexOf.call(th.parentNode.children,th);dir=(idx===lastCol)?-dir:1;lastCol=idx;var tb=document.querySelector('#t tbody');rows.sort(function(a,b){var x=cell(a,idx),y=cell(b,idx);return (x<y?-1:x>y?1:0)*dir;});rows.forEach(function(r){tb.appendChild(r)});}
function cell(r,i){var td=r.children[i];if(td.dataset.n!==undefined)return parseInt(td.dataset.n);var t=td.textContent.trim();var n=parseFloat(t);return isNaN(n)?t.toLowerCase():n;}
document.querySelector('.pill').classList.add('on');
</script>`
