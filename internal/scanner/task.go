package scanner

// taskKind selects how a worker processes a task. Most tasks are taskNormal
// (path fuzzing); the others carry a different request shape.
type taskKind int

const (
	taskNormal   taskKind = iota
	taskFavicon           // fetch /favicon.ico and fingerprint it
	taskVHost             // fuzz the Host header instead of the path
	taskTakeover          // fetch the target root and fingerprint subdomain-takeover
)

type Task struct {
	TargetURL string
	Path      string
	Depth     int // directory recursion depth (bounded by --depth)
	ExtDepth  int // link-extraction depth (bounded by --extract-depth)

	Kind taskKind
	Host string // Host-header value for taskVHost

	// BaseKey overrides which calibration baseline this task is matched against.
	// Empty means the target root; recursion sets it to the discovered directory
	// so a subdir's own soft-404 fingerprint is used.
	BaseKey string

	// Subs holds keyword→word substitutions for multi-wordlist
	// (clusterbomb/pitchfork) fuzzing. When set, the URL is built by replacing
	// each keyword in the target; when nil, Path is appended/substituted instead.
	Subs map[string]string
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
	SecretFound bool     `json:"secret_found"`
	SecretTypes []string `json:"secret_types,omitempty"`
	WAFDetected string   `json:"waf_detected,omitempty"`
}
