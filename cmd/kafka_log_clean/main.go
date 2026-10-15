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

var Version = "1.0.1"

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

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("kafka_log_clean", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("c", "", "YAML config (omit + obfuscate)")
	input := fs.String("i", "", "Input file, directory, or .zip")
	output := fs.String("o", "", "Output file, directory, or .zip")
	reportPath := fs.String("r", "", "Replacement report path (default: report-<input>.yaml)")
	workers := fs.Int("w", runtime.NumCPU(), "Worker threads")
	stdin := fs.Bool("stdin", false, "Read stdin, write stdout")
	verbose := fs.Bool("v", false, "Print per-file process output")
	fs.BoolVar(verbose, "verbose", false, "Print per-file process output")
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
	clean.Verbose = *verbose
	fmt.Fprintf(os.Stderr, "[%s %s] starting\n", "kafka_log_clean", Version)

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
	rep := *reportPath
	if rep == "" || rep == "report.yaml" {
		rep = defaultReportName(inp)
	}

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
	case clean.IsMultiArchive(inp):
		fmt.Fprintf(os.Stderr, "extract: %s\n", inp)
		n, err := clean.ExtractArchive(inp, srcRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "extract: %d files\n", n)
		fmt.Fprintf(os.Stderr, "process: tree %s workers=%d\n", srcRoot, *workers)
		if err := clean.ProcessTree(c, srcRoot, dstRoot, *workers); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if clean.IsMultiArchive(out) {
			if err := clean.WriteArchive(dstRoot, out); err != nil {
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
		if clean.IsMultiArchive(out) {
			target = dstRoot
		}
		fmt.Fprintf(os.Stderr, "process: tree %s workers=%d\n", inp, *workers)
		if err := clean.ProcessTree(c, inp, target, *workers); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if clean.IsMultiArchive(out) {
			if err := clean.WriteArchive(dstRoot, out); err != nil {
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
			cleaned := clean.ProcessBytes(c, data, rel)
			if strings.EqualFold(filepath.Ext(out), ".zip") {
				_ = os.MkdirAll(filepath.Dir(out), 0o755)
				// write single-file zip via temp dir
				tmpf := filepath.Join(dstRoot, c.ObfuscatePath(rel))
				_ = os.MkdirAll(filepath.Dir(tmpf), 0o755)
				_ = os.WriteFile(tmpf, cleaned, 0o644)
				if err := clean.WriteZip(dstRoot, out); err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					return 1
				}
			} else {
				_ = os.MkdirAll(filepath.Dir(out), 0o755)
				if err := os.WriteFile(out, cleaned, 0o644); err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					return 1
				}
			}
			c.AddProcessed()
		}
	}

	omitted := append([]string{}, c.Omitted...)
	rpt := report{
		Tool:           "kafka_log_clean",
		Version:        Version,
		Input:          inp,
		Output:         out,
		ProcessedFiles: c.Processed,
		OmittedFiles:   omitted,
		Replacements:   c.Store.Report(),
		Config:         cfg,
		Warning:        "Do not share this report. It maps original values to replacements.",
	}
	b, err := yaml.Marshal(rpt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if err := os.WriteFile(rep, b, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("cleaned: %s\n", out)
	fmt.Printf("report:  %s  (keep private)\n", rep)
	fmt.Printf("files:   %d processed, %d omitted\n", c.Processed, len(c.Omitted))
	printReplacementSummary(c)
	return 0
}

func resolveOutput(inp, output string) string {
	if output != "" {
		abs, _ := filepath.Abs(output)
		return abs
	}
	if clean.IsMultiArchive(inp) {
		return filepath.Join(filepath.Dir(inp), "scrubbed-"+filepath.Base(inp))
	}
	info, err := os.Stat(inp)
	if err == nil && !info.IsDir() {
		ext := filepath.Ext(inp)
		return strings.TrimSuffix(inp, ext) + ".cleaned" + ext
	}
	return inp + "-cleaned"
}

func defaultReportName(inp string) string {
	base := filepath.Base(inp)
	stem := base
	lower := strings.ToLower(base)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		stem = base[:len(base)-len(".tar.gz")]
	case strings.HasSuffix(lower, ".tgz"):
		stem = base[:len(base)-len(".tgz")]
	case strings.HasSuffix(lower, ".tar"):
		stem = base[:len(base)-len(".tar")]
	case strings.HasSuffix(lower, ".zip"):
		stem = base[:len(base)-len(".zip")]
	case strings.HasSuffix(lower, ".gz"):
		stem = base[:len(base)-len(".gz")]
	}
	stem = strings.TrimSpace(stem)
	if stem == "" || stem == "." {
		stem = "input"
	}
	stem = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return '-'
		default:
			return r
		}
	}, stem)
	return "report-" + stem + ".yaml"
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
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func printReplacementSummary(c *clean.Cleaner) {
	reps := c.Store.Report()
	fmt.Printf("mappings: %d unique replacements\n", len(reps))
	if len(c.Omitted) > 0 && len(c.Omitted) <= 20 {
		for _, o := range c.Omitted {
			fmt.Printf("  omitted %s\n", o)
		}
	} else if len(c.Omitted) > 20 {
		fmt.Printf("  omitted %d files (see report.yaml)\n", len(c.Omitted))
	}
}
