package detection

import "testing"

func TestCVEsForServer(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		wantIDs  []string
		wantNone bool
	}{
		{"apache vulnerable 2.4.49", "Apache/2.4.49 (Unix)", []string{"CVE-2021-41773"}, false},
		{"apache vulnerable 2.4.50", "Apache/2.4.50", []string{"CVE-2021-42013"}, false},
		{"apache patched", "Apache/2.4.62", nil, true},
		{"nginx in range", "nginx/1.10.3", []string{"CVE-2017-7529"}, false},
		{"nginx patched", "nginx/1.25.0", nil, true},
		{"multi product", "Apache/2.4.49 PHP/7.4.0", []string{"CVE-2021-41773", "CVE-2019-11043"}, false},
		{"empty", "", nil, true},
		{"no version", "nginx", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CVEsForServer(tt.header)
			if tt.wantNone {
				if len(got) != 0 {
					t.Fatalf("expected no CVEs, got %v", got)
				}
				return
			}
			ids := make(map[string]bool)
			for _, c := range got {
				ids[c.ID] = true
				if c.Severity == "" || c.Description == "" {
					t.Errorf("CVE %s missing metadata", c.ID)
				}
			}
			for _, want := range tt.wantIDs {
				if !ids[want] {
					t.Errorf("expected %s in %v", want, ids)
				}
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"1.2.3", "1.2.4", -1},
		{"2.0", "1.9.9", 1},
		{"1.13.2", "1.13.10", -1},
		{"2.4.49", "2.4.9", 1},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	if !versionInRange("1.5.0", "1.0.0", "2.0.0") {
		t.Error("1.5.0 should be in [1.0.0, 2.0.0]")
	}
	if versionInRange("3.0.0", "1.0.0", "2.0.0") {
		t.Error("3.0.0 should be out of range")
	}
	if !versionInRange("5.0", "", "9.0") {
		t.Error("unbounded lower should include 5.0")
	}
	if !versionInRange("5.0", "1.0", "") {
		t.Error("unbounded upper should include 5.0")
	}
}
