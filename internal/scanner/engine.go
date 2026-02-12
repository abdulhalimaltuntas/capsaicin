package scanner

import (
	"bufio"
	"context"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/detection"
	"github.com/capsaicin/scanner/internal/transport"
)

type Engine struct {
	config     config.Config
	client     *transport.Client
	calCache   *detection.CalibrationCache
	stats      *Stats
	statsReady chan struct{}
}

func NewEngine(cfg config.Config) *Engine {
	client := transport.NewClient(
		cfg.Timeout,
		cfg.RateLimit,
		cfg.RetryAttempts,
		cfg.MaxResponseMB,
	)

	return &Engine{
		config:     cfg,
		client:     client,
		calCache:   detection.NewCalibrationCache(),
		statsReady: make(chan struct{}),
	}
}

// WaitForStats blocks until the scan engine has initialized its Stats.
// Safe to call from a different goroutine than RunWithEvents.
func (e *Engine) WaitForStats() *Stats {
	<-e.statsReady
	return e.stats
}

// WaitForStatsCtx blocks until the scan engine has initialized its Stats,
// or the context is cancelled. Returns nil if context is cancelled first.
func (e *Engine) WaitForStatsCtx(ctx context.Context) *Stats {
	select {
	case <-e.statsReady:
		return e.stats
	case <-ctx.Done():
		return nil
	}
}

func (e *Engine) Run(targets []string) ([]Result, *Stats, error) {
	return e.RunContext(context.Background(), targets)
}

func (e *Engine) RunContext(ctx context.Context, targets []string) ([]Result, *Stats, error) {
	return e.RunWithEvents(ctx, targets, nil)
}

func (e *Engine) RunWithEvents(ctx context.Context, targets []string, eventCh chan<- ScanEvent) ([]Result, *Stats, error) {
	if eventCh != nil {
		defer close(eventCh)
	}

	words, err := loadWordlist(e.config.Wordlist)
	if err != nil {
		return nil, nil, err
	}

	initialTaskCount := int64(len(targets) * len(words) * (1 + len(e.config.Extensions)))
	stats := NewStats(initialTaskCount)

	// Expose stats to callers waiting on WaitForStats().
	e.stats = stats
	close(e.statsReady)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return nil, stats, ctx.Err()
		default:
		}
		detection.PerformCalibration(ctx, target, e.client.HTTPClient(), e.config.CustomHeaders, e.calCache)
	}

	var results []Result
	var resultsMutex sync.Mutex
	dedup := NewDeduplicator()

	scannedDirs := make(map[string]map[string]bool)
	var dirMutex sync.Mutex

	taskChan := make(chan Task, e.config.Threads*2)
	resultChan := make(chan Result, e.config.Threads*2)
	newTaskChan := make(chan Task, e.config.Threads*2)

	var taskWg sync.WaitGroup
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range resultChan {
			r := result // copy for pointer
			if dedup.Add(&r) {
				resultsMutex.Lock()
				results = append(results, r)
				resultsMutex.Unlock()

				// Emit live result event to UI.
				if eventCh != nil {
					select {
					case eventCh <- ScanEvent{Type: EventResultFound, Result: &r}:
					case <-ctx.Done():
					}
				}
			}

			if result.WAFDetected != "" {
				stats.IncrementWAFHits()
			}
		}
	}()

	if e.config.MaxDepth > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for newTask := range newTaskChan {
				select {
				case <-ctx.Done():
					taskWg.Done()
					continue
				default:
				}

				dirMutex.Lock()
				if scannedDirs[newTask.TargetURL] == nil {
					scannedDirs[newTask.TargetURL] = make(map[string]bool)
				}
				if !scannedDirs[newTask.TargetURL][newTask.Path] && newTask.Depth <= e.config.MaxDepth {
					scannedDirs[newTask.TargetURL][newTask.Path] = true
					dirMutex.Unlock()

					for _, word := range words {
						taskWg.Add(1)
						task := Task{
							TargetURL: newTask.TargetURL,
							Path:      strings.TrimSuffix(newTask.Path, "/") + "/" + word,
							Depth:     newTask.Depth,
						}
						select {
						case taskChan <- task:
						case <-ctx.Done():
							taskWg.Done()
							goto skipExtensions
						}
						stats.IncrementTotal(1)

						for _, ext := range e.config.Extensions {
							taskWg.Add(1)
							taskWithExt := Task{
								TargetURL: newTask.TargetURL,
								Path:      strings.TrimSuffix(newTask.Path, "/") + "/" + word + ext,
								Depth:     newTask.Depth,
							}
							select {
							case taskChan <- taskWithExt:
							case <-ctx.Done():
								taskWg.Done()
								goto skipExtensions
							}
							stats.IncrementTotal(1)
						}
					}
				skipExtensions:
					taskWg.Done()
				} else {
					dirMutex.Unlock()
					taskWg.Done()
				}
			}
		}()
	}

	workerDone := make(chan struct{}, e.config.Threads)
	for i := 0; i < e.config.Threads; i++ {
		workerRng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(i)))
		go worker(
			ctx,
			taskChan,
			resultChan,
			newTaskChan,
			e.config,
			e.client,
			stats,
			e.calCache,
			workerDone,
			&taskWg,
			workerRng,
			eventCh,
		)
	}

	taskWg.Add(int(initialTaskCount))

	go func() {
		sentCount := int64(0)
		for _, target := range targets {
			for _, word := range words {
				task := Task{TargetURL: target, Path: word, Depth: 1}
				select {
				case taskChan <- task:
					sentCount++
				case <-ctx.Done():
					remaining := initialTaskCount - sentCount
					if remaining > 0 {
						taskWg.Add(int(-remaining))
					}
					return
				}

				for _, ext := range e.config.Extensions {
					taskWithExt := Task{TargetURL: target, Path: word + ext, Depth: 1}
					select {
					case taskChan <- taskWithExt:
						sentCount++
					case <-ctx.Done():
						remaining := initialTaskCount - sentCount
						if remaining > 0 {
							taskWg.Add(int(-remaining))
						}
						return
					}
				}
			}
		}
	}()

	go func() {
		taskWg.Wait()
		close(taskChan)
	}()

	go func() {
		for i := 0; i < e.config.Threads; i++ {
			<-workerDone
		}
		close(resultChan)
		if e.config.MaxDepth > 0 {
			close(newTaskChan)
		}
	}()

	wg.Wait()

	return results, stats, nil
}

func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	estimatedLines := 1024
	if info, err := file.Stat(); err == nil && info.Size() > 0 {
		estimatedLines = int(info.Size() / 8)
	}

	words := make([]string, 0, estimatedLines)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	return words, scanner.Err()
}

func CountWordlist(path string) (int, error) {
	words, err := loadWordlist(path)
	if err != nil {
		return 0, err
	}
	return len(words), nil
}
