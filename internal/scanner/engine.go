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
	config   config.Config
	client   *transport.Client
	calCache *detection.CalibrationCache
	rng      *rand.Rand
	rngMu    sync.Mutex
}

func NewEngine(cfg config.Config) *Engine {
	client := transport.NewClient(
		cfg.Timeout,
		cfg.RateLimit,
		cfg.RetryAttempts,
		cfg.MaxResponseMB,
	)

	return &Engine{
		config:   cfg,
		client:   client,
		calCache: detection.NewCalibrationCache(),
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (e *Engine) Run(targets []string) ([]Result, *Stats, error) {
	return e.RunContext(context.Background(), targets)
}

func (e *Engine) RunContext(ctx context.Context, targets []string) ([]Result, *Stats, error) {
	words, err := loadWordlist(e.config.Wordlist)
	if err != nil {
		return nil, nil, err
	}

	initialTaskCount := int64(len(targets) * len(words) * (1 + len(e.config.Extensions)))
	stats := NewStats(initialTaskCount)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return nil, stats, ctx.Err()
		default:
		}
		detection.PerformCalibration(target, e.client.HTTPClient(), e.config.CustomHeaders, e.calCache)
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
			e.rng,
			&e.rngMu,
		)
	}

	taskWg.Add(int(initialTaskCount))

	go func() {
		for _, target := range targets {
			for _, word := range words {
				task := Task{TargetURL: target, Path: word, Depth: 1}
				select {
				case taskChan <- task:
				case <-ctx.Done():
					return
				}

				for _, ext := range e.config.Extensions {
					taskWithExt := Task{TargetURL: target, Path: word + ext, Depth: 1}
					select {
					case taskChan <- taskWithExt:
					case <-ctx.Done():
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
