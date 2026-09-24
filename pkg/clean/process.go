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
		"log4j.properties", "log4j2.yaml", "log4j2.properties":
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
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(c.ObfuscateText(string(inner))))
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
	if workers < 1 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var first error
	var mu sync.Mutex
	for _, f := range files {
		f := f
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rel, err := filepath.Rel(src, f)
			if err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
				return
			}
			rel = filepath.ToSlash(rel)
			if c.ShouldOmit(rel) {
				c.AddOmitted(rel)
				Logf("omit   %s", rel)
				return
			}
			data, err := os.ReadFile(f)
			if err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
				return
			}
			outRel := c.ObfuscatePath(rel)
			target := filepath.Join(dst, filepath.FromSlash(outRel))
			_ = os.MkdirAll(filepath.Dir(target), 0o755)
			cleaned := ProcessBytes(c, data, filepath.Base(f))
			if err := os.WriteFile(target, cleaned, 0o644); err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
				return
			}
			c.AddProcessed()
			Logf("clean  %s -> %s (%d bytes)", rel, outRel, len(cleaned))
		}()
	}
	wg.Wait()
	return first
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
