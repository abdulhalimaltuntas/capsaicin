package smartfuzz

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"
)

// WordGenerator provides a unified interface for generating scan words from
// multiple sources: static wordlists, target-aware spidering, and mutations.
type WordGenerator struct {
	spider  *Spider
	mutator *Mutator

	// Configuration
	EnableSpider   bool   // Crawl target for seed words
	EnableMutation bool   // Apply mutation rules
	WordlistPath   string // Static wordlist path (optional)
}

// NewWordGenerator creates a generator with all sub-components.
func NewWordGenerator(wordlistPath string, enableSpider, enableMutation bool) *WordGenerator {
	return &WordGenerator{
		spider:         NewSpider(10 * time.Second),
		mutator:        NewMutator(),
		EnableSpider:   enableSpider,
		EnableMutation: enableMutation,
		WordlistPath:   wordlistPath,
	}
}

// Generate produces the complete word list for scanning a target.
// It merges static wordlist entries, spider-crawled paths, and mutations
// into a single deduplicated stream.
func (wg *WordGenerator) Generate(ctx context.Context, targetURL string) ([]string, error) {
	seen := make(map[string]bool)
	var allWords []string

	addWord := func(w string) {
		w = strings.TrimSpace(w)
		if w != "" && !seen[w] {
			seen[w] = true
			allWords = append(allWords, w)
		}
	}

	// 1. Load static wordlist if provided.
	if wg.WordlistPath != "" {
		staticWords, err := loadWordlistFile(wg.WordlistPath)
		if err != nil {
			return nil, err
		}
		for _, w := range staticWords {
			addWord(w)
		}
	}

	// 2. Spider-crawl the target for dynamic seeds.
	if wg.EnableSpider && targetURL != "" {
		crawlResult, err := wg.spider.Crawl(ctx, targetURL)
		if err == nil {
			for _, p := range crawlResult.Paths {
				// Clean path for use as scan word.
				p = strings.TrimPrefix(p, "/")
				addWord(p)
			}
			for _, w := range crawlResult.Words {
				addWord(w)
			}
			for _, h := range crawlResult.APIHints {
				h = strings.TrimPrefix(h, "/")
				addWord(h)
			}
		}
		// Spider errors are non-fatal; we still have the static wordlist.
	}

	// 3. Apply mutations to generate permutations.
	if wg.EnableMutation && len(allWords) > 0 {
		// Only mutate the first N words to avoid combinatorial explosion.
		seedLimit := 500
		if len(allWords) < seedLimit {
			seedLimit = len(allWords)
		}

		seeds := allWords[:seedLimit]
		mutated := wg.mutator.MutateBatch(seeds)

		// Cap total mutations to prevent memory blow-up.
		mutationCap := 50000
		count := 0
		for _, m := range mutated {
			if count >= mutationCap {
				break
			}
			addWord(m)
			count++
		}
	}

	return allWords, nil
}

// GenerateChan streams words into a channel for memory-efficient integration
// with the existing task pipeline.
func (wg *WordGenerator) GenerateChan(ctx context.Context, targetURL string, out chan<- string) error {
	words, err := wg.Generate(ctx, targetURL)
	if err != nil {
		return err
	}

	go func() {
		defer close(out)
		for _, w := range words {
			select {
			case out <- w:
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func loadWordlistFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}
