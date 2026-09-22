package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nwlterry/kafka_log_clean/pkg/clean"

	"gopkg.in/yaml.v3"
)

var Version = "1.1.0"

type report struct {
	Tool           string              `yaml:"tool"`
	Version        string              `yaml:"version"`
	Input          string              `yaml:"input"`
	Output         string              `yaml:"output"`
	ProcessedFiles int                 `yaml:"processedFiles"`
	OmittedFiles   []string            `yaml:"omittedFiles"`
	Replacements   []clean.Replacement `yaml:"replacements"`
	Config         clean.Config        `yaml:"config"`
	Warning        string              `yaml:"warning"`
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("kafka_log_clean", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("c", "", "YAML config")
	input := fs.String("i", "", "Input file, directory, or .zip")
	output := fs.String("o", "", "Output file, directory, or .zip")
	reportPath := fs.String("r", "report.yaml", "Replacement report path")
	workers := fs.Int("w", runtime.NumCPU(), "Worker threads")
	stdin := fs.Bool("stdin", false, "Read stdin, write stdout")
	showVersion := fs.Bool("version", false, "Print version")
	printDefault := fs.Bool("print-default-config", false, "Print built-in config")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println(Version)
		return 0
	}
	if *printDefault {
		enc := yaml.NewEncoder(os.Stdout)
		enc.SetIndent(2)
		_ = enc.Encode(map[string]any{"config": clean.DefaultConfig()})
		_ = enc.Close()
		return 0
	}
	cfg := clean.DefaultConfig()
	if *configPath != "" {
		loaded, err := clean.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		cfg = loaded
	}
	c := clean.NewCleaner(cfg, nil)
	if *stdin || (*input == "" && !isTTY()) {
		data, _ := io.ReadAll(os.Stdin)
		fmt.Print(c.ObfuscateText(string(data)))
		return 0
	}
	if *input == "" {
		fmt.Fprintln(os.Stderr, "error: provide -i or pipe text on stdin")
		return 2
	}
	inp, err := filepath.Abs(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if _, err := os.Stat(inp); err != nil {
		fmt.Fprintf(os.Stderr, "error: input not found: %s\n", inp)
		return 2
	}
	out := resolveOutput(inp, *output)
	tmp, err := os.MkdirTemp("", "kafka_log_clean_*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	defer os.RemoveAll(tmp)
	srcRoot := filepath.Join(tmp, "src")
	dstRoot := filepath.Join(tmp, "dst")
	_ = os.MkdirAll(srcRoot, 0o755)
	_ = os.MkdirAll(dstRoot, 0o755)
	info, _ := os.Stat(inp)
	switch {
	case strings.EqualFold(filepath.Ext(inp), ".zip"):
		if err := clean.ExtractZip(inp, srcRoot); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if err := clean.ProcessTree(c, srcRoot, dstRoot, *workers); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if strings.EqualFold(filepath.Ext(out), ".zip") {
			if err := clean.WriteZip(dstRoot, out); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
		} else {
			_ = os.RemoveAll(out)
			if err := copyTree(dstRoot, out); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
		}
	case info.IsDir():
		target := out
		if strings.EqualFold(filepath.Ext(out), ".zip") {
			target = dstRoot
		}
		if err := clean.ProcessTree(c, inp, target, *workers); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if strings.EqualFold(filepath.Ext(out), ".zip") {
			if err := clean.WriteZip(dstRoot, out); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
		}
	default:
		rel := filepath.Base(inp)
		if c.ShouldOmit(rel) {
			c.AddOmitted(rel)
		} else {
			data, err := os.ReadFile(inp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
			_ = os.MkdirAll(filepath.Dir(out), 0o755)
			if err := os.WriteFile(out, clean.ProcessBytes(c, data, rel), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
			c.AddProcessed()
		}
	}
	b, err := yaml.Marshal(report{
		Tool: "kafka_log_clean", Version: Version, Input: inp, Output: out,
		ProcessedFiles: c.Processed, OmittedFiles: append([]string{}, c.Omitted...),
		Replacements: c.Store.Report(), Config: cfg,
		Warning: "Do not share this report. It maps original values to replacements.",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*reportPath, b, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("cleaned: %s\nreport:  %s  (keep private)\nfiles:   %d processed, %d omitted\n", out, *reportPath, c.Processed, len(c.Omitted))
	return 0
}

func resolveOutput(inp, output string) string {
	if output != "" {
		abs, _ := filepath.Abs(output)
		return abs
	}
	if strings.EqualFold(filepath.Ext(inp), ".zip") {
		return filepath.Join(filepath.Dir(inp), "scrubbed-"+filepath.Base(inp))
	}
	info, err := os.Stat(inp)
	if err == nil && !info.IsDir() {
		ext := filepath.Ext(inp)
		return strings.TrimSuffix(inp, ext) + ".cleaned" + ext
	}
	return inp + "-cleaned"
}

func isTTY() bool {
	st, err := os.Stdin.Stat()
	if err != nil {
		return true
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_ = os.MkdirAll(filepath.Dir(target), 0o755)
		return os.WriteFile(target, data, 0o644)
	})
}
