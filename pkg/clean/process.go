package clean

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var textExt = map[string]struct{}{
	".log": {}, ".txt": {}, ".json": {}, ".ndjson": {}, ".yml": {}, ".yaml": {},
	".xml": {}, ".csv": {}, ".properties": {}, ".conf": {}, ".cfg": {}, ".ini": {},
	".out": {}, ".err": {}, ".md": {}, ".html": {}, ".js": {}, ".sh": {}, ".bat": {}, ".ps1": {},
}

var binExt = map[string]struct{}{
	".p12": {}, ".jks": {}, ".keystore": {}, ".truststore": {},
	".so": {}, ".dll": {}, ".exe": {}, ".bin": {},
}

func isText(name string, sample []byte) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if _, ok := binExt[ext]; ok {
		return false
	}
	base := strings.ToLower(filepath.Base(name))
	if _, ok := textExt[ext]; ok {
		return true
	}
	switch base {
	case "server.properties", "producer.properties", "consumer.properties",
		"connect-distributed.properties", "kafka_server_jaas.conf",
		"log4j.properties", "log4j2.yaml", "log4j2.properties",
		"kafka-authorizer.log", "authorizer.log":
		return true
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	return true
}

func ProcessBytes(c *Cleaner, data []byte, name string) []byte {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".gz") && !strings.HasSuffix(lower, ".tar.gz") {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return data
		}
		inner, err := io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			return data
		}
		cleaned := []byte(c.ObfuscateText(string(inner)))
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(cleaned)
		_ = zw.Close()
		return buf.Bytes()
	}
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	if !isText(name, sample) {
		return data
	}
	return []byte(c.ObfuscateText(string(data)))
}

func walkFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

func ProcessTree(c *Cleaner, src, dst string, workers int) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	files, err := walkFiles(src)
	if err != nil {
		return err
	}
	Logf("process: %d files found under %s", len(files), src)
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(files) && len(files) > 0 {
		workers = len(files)
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	var first error
	var mu sync.Mutex
	var done int

	worker := func() {
		defer wg.Done()
		for f := range jobs {
			rel, err := filepath.Rel(src, f)
			if err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
				continue
			}
			rel = filepath.ToSlash(rel)
			if c.ShouldOmit(rel) {
				c.AddOmitted(rel)
				Logf("omit   %s", rel)
				continue
			}
			Logf("start  %s", rel)
			data, err := os.ReadFile(f)
			if err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
				continue
			}
			outRel := c.ObfuscatePath(rel)
			target := filepath.Join(dst, filepath.FromSlash(outRel))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
				continue
			}
			var cleaned []byte
			if IsMultiArchive(filepath.Base(f)) {
				// Nested expand/scan/repack runs inline on this worker.
				// Do not open another worker pool — that fills every slot
				// and the outer pool never advances past the first N archives.
				cleaned, err = processNestedArchive(c, data, filepath.Base(f))
				if err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
					continue
				}
			} else {
				cleaned = ProcessBytes(c, data, filepath.Base(f))
			}
			if err := os.WriteFile(target, cleaned, 0o644); err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
				continue
			}
			c.AddProcessed()
			mu.Lock()
			done++
			n := done
			mu.Unlock()
			Logf("clean  %s -> %s (%d bytes) [%d/%d]", rel, outRel, len(cleaned), n, len(files))
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	for _, f := range files {
		jobs <- f
	}
	close(jobs)
	wg.Wait()
	return first
}

// processNestedArchive expands a zip/tar/tar.gz found inside the tree, cleans
// its contents on this same worker (no extra pool), and re-packs.
func processNestedArchive(c *Cleaner, data []byte, name string) ([]byte, error) {
	tmp, err := os.MkdirTemp("", "logclean-nested-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(tmp, "src")
	dst := filepath.Join(tmp, "dst")
	inFile := filepath.Join(tmp, name)
	if err := os.WriteFile(inFile, data, 0o644); err != nil {
		return nil, err
	}
	n, err := ExtractArchive(inFile, src)
	if err != nil {
		return nil, err
	}
	Logf("extract nested %s (%d files)", name, n)
	if err := ProcessTree(c, src, dst, 1); err != nil {
		return nil, err
	}
	outFile := filepath.Join(tmp, "out-"+name)
	if err := WriteArchive(dst, outFile); err != nil {
		return nil, err
	}
	return os.ReadFile(outFile)
}

func ExtractZip(archive, dest string) (int, error) {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	n := 0
	for _, f := range r.File {
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(dest)+string(os.PathSeparator)) &&
			filepath.Clean(target) != filepath.Clean(dest) {
			continue
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(target), 0o755)
		rc, err := f.Open()
		if err != nil {
			return n, err
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return n, err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func WriteZip(srcDir, archive string) error {
	if err := os.MkdirAll(filepath.Dir(archive), 0o755); err != nil && filepath.Dir(archive) != "." {
		return err
	}
	f, err := os.Create(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	files, err := walkFiles(srcDir)
	if err != nil {
		return err
	}
	for _, p := range files {
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}
