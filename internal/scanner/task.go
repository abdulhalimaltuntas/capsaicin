package scanner

type Task struct {
	TargetURL string
	Path      string
	Depth     int
}

type Result struct {
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	Size        int      `json:"size"`
	WordCount   int      `json:"word_count"`
	LineCount   int      `json:"line_count"`
	Critical    bool     `json:"critical"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Tags        []string `json:"tags,omitempty"`
	Method      string   `json:"method"`
	Timestamp   string   `json:"timestamp"`
	Server      string   `json:"server,omitempty"`
	PoweredBy   string   `json:"powered_by,omitempty"`
	UserAgent   string   `json:"user_agent"`
	SecretFound  bool     `json:"secret_found"`
	SecretTypes  []string `json:"secret_types,omitempty"`
	WAFDetected  string   `json:"waf_detected,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}
