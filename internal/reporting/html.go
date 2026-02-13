package reporting

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/scanner"
)

func GenerateHTML(results []scanner.Result, filename string) error {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Capsaicin Scan Report</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			background: #f5f5f5;
			padding: 20px;
			color: #333;
		}
		.container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
		h1 { font-size: 24px; margin-bottom: 10px; color: #222; }
		.meta { color: #666; font-size: 14px; margin-bottom: 30px; }
		.stats {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
			gap: 15px;
			margin-bottom: 30px;
		}
		.stat-card { background: #f9f9f9; padding: 15px; border-radius: 6px; border-left: 3px solid #007bff; }
		.stat-value { font-size: 24px; font-weight: bold; color: #007bff; }
		.stat-label { font-size: 12px; color: #666; margin-top: 5px; }
		.search-box { margin-bottom: 20px; }
		#searchInput {
			width: 100%%;
			padding: 12px;
			font-size: 14px;
			border: 1px solid #ddd;
			border-radius: 6px;
		}
		table { width: 100%%; border-collapse: collapse; font-size: 14px; }
		th { background: #f0f0f0; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #ddd; }
		td { padding: 10px 12px; border-bottom: 1px solid #eee; }
		tr:hover { background: #f9f9f9; }
		.status-200 { color: #28a745; font-weight: 600; }
		.status-300 { color: #007bff; font-weight: 600; }
		.status-400 { color: #dc3545; font-weight: 600; }
		.status-500 { color: #ffc107; font-weight: 600; }
		.badge {
			display: inline-block;
			padding: 3px 8px;
			border-radius: 4px;
			font-size: 11px;
			font-weight: 600;
			margin-left: 5px;
		}
		.badge-critical { background: #dc3545; color: white; }
		.badge-secret { background: #ffc107; color: #333; }
		.badge-waf { background: #6f42c1; color: white; }
		.badge-tech { background: #17a2b8; color: white; }
		code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 13px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>Capsaicin Scan Report</h1>
		<div class="meta">Generated: %s</div>

		<div class="stats">
			<div class="stat-card">
				<div class="stat-value">%d</div>
				<div class="stat-label">Total Findings</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">%d</div>
				<div class="stat-label">Success (2xx)</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">%d</div>
				<div class="stat-label">Redirects (3xx)</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">%d</div>
				<div class="stat-label">Critical</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">%d</div>
				<div class="stat-label">Secrets</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">%d</div>
				<div class="stat-label">WAF Detected</div>
			</div>
		</div>

		<div class="search-box">
			<input type="text" id="searchInput" placeholder="Search findings...">
		</div>

		<table id="resultsTable">
			<thead>
				<tr>
					<th>Status</th>
					<th>URL</th>
					<th>Size</th>
					<th>Details</th>
				</tr>
			</thead>
			<tbody>
				%s
			</tbody>
		</table>
	</div>

	<script>
		document.getElementById('searchInput').addEventListener('input', function(e) {
			const searchTerm = e.target.value.toLowerCase();
			const rows = document.querySelectorAll('#resultsTable tbody tr');
			
			rows.forEach(row => {
				const text = row.textContent.toLowerCase();
				row.style.display = text.includes(searchTerm) ? '' : 'none';
			});
		});
	</script>
</body>
</html>`

	var tableRows strings.Builder
	count2xx := 0
	count3xx := 0
	countCritical := 0
	countSecrets := 0
	countWAF := 0

	for _, result := range results {
		statusClass := "status-200"
		if result.StatusCode >= 300 && result.StatusCode < 400 {
			statusClass = "status-300"
			count3xx++
		} else if result.StatusCode >= 400 && result.StatusCode < 500 {
			statusClass = "status-400"
		} else if result.StatusCode >= 500 {
			statusClass = "status-500"
		} else if result.StatusCode >= 200 && result.StatusCode < 300 {
			count2xx++
		}

		if result.Critical {
			countCritical++
		}
		if result.SecretFound {
			countSecrets++
		}
		if result.WAFDetected != "" {
			countWAF++
		}

		badges := ""
		if result.Critical {
			badges += `<span class="badge badge-critical">CRITICAL</span>`
		}
		if result.SecretFound {
			badges += fmt.Sprintf(`<span class="badge badge-secret">SECRET: %s</span>`, strings.Join(result.SecretTypes, ", "))
		}
		if result.WAFDetected != "" {
			badges += fmt.Sprintf(`<span class="badge badge-waf">WAF: %s</span>`, result.WAFDetected)
		}
		if len(result.Technologies) > 0 {
			badges += fmt.Sprintf(`<span class="badge badge-tech">%s</span>`, strings.Join(result.Technologies, ", "))
		}

		details := badges
		if result.Server != "" || result.PoweredBy != "" {
			tech := []string{}
			if result.Server != "" {
				tech = append(tech, result.Server)
			}
			if result.PoweredBy != "" {
				tech = append(tech, result.PoweredBy)
			}
			if len(details) > 0 {
				details += " "
			}
			details += fmt.Sprintf(`<code>%s</code>`, strings.Join(tech, ", "))
		}

		tableRows.WriteString(fmt.Sprintf(`
				<tr>
					<td class="%s">%d</td>
					<td><code>%s</code></td>
					<td>%d bytes</td>
					<td>%s</td>
				</tr>`,
			statusClass, result.StatusCode, result.URL, result.Size, details))
	}

	finalHTML := fmt.Sprintf(htmlTemplate,
		time.Now().Format("2006-01-02 15:04:05"),
		len(results),
		count2xx,
		count3xx,
		countCritical,
		countSecrets,
		countWAF,
		tableRows.String())

	return os.WriteFile(filename, []byte(finalHTML), 0644)
}