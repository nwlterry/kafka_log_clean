package clean

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	ipv4OnlyRe = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`)
	ipv6Re     = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b`)
	macRe      = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}`)
	emailRe    = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	pemRe      = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`)
)

var localIPv4 = map[string]struct{}{"127.0.0.1": {}, "0.0.0.0": {}, "255.255.255.255": {}}
var localIPv6 = map[string]struct{}{"::1": {}, "::": {}}

type secretPat struct {
	re   *regexp.Regexp
	repl string
}

var defaultSecrets = []secretPat{
	{regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(basic|bearer)\s+[A-Za-z0-9+/=._\-]+`), `${1}${2} x-redacted-auth-x`},
	{regexp.MustCompile(`(?i)((?:password|passwd|username)\s*=\s*)(?:"[^"]+"|'[^']+'|[^\s;"']+)`), `${1}x-redacted-secret-x`},
	{regexp.MustCompile(`(?i)((?:ssl\.(?:keystore|truststore|key)\.password|ssl\.keystore\.key|sasl\.jaas\.config|confluent\.license|basic\.auth\.user\.info|schema\.registry\.basic\.auth\.user\.info|producer\.sasl\.jaas\.config|consumer\.sasl\.jaas\.config|admin\.sasl\.jaas\.config|ldap\.java\.naming\.security\.credentials|confluent\.metadata\.sasl\.jaas\.config)\s*[=:]\s*)([^\s,]+)`), `${1}x-redacted-secret-x`},
	{regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key|sasl\.password)\s*[=:]\s*)([^\s,"'}]+)`), `${1}x-redacted-secret-x`},
	{regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|api_key|authorization|jaas)"\s*:\s*")([^"]+)"`), `${1}x-redacted-secret-x"`},
	{regexp.MustCompile(`(?i)(://[^:/@\s]+:)([^@/\s]+)(@)`), `${1}x-redacted-secret-x${3}`},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), `x-redacted-awskey-x`},
}

type Occurrence struct {
	Original string `yaml:"original"`
	Count    int    `yaml:"count"`
}

type Replacement struct {
	Canonical    string       `yaml:"canonical"`
	ReplacedWith string       `yaml:"replacedWith"`
	Occurrences  []Occurrence `yaml:"occurrences"`
	occ          map[string]int
}

type MappingStore struct {
	mu      sync.Mutex
	maps    map[string]map[string]string
	counter map[string]int
	recs    map[string]*Replacement
}

func NewMappingStore() *MappingStore {
	return &MappingStore{maps: map[string]map[string]string{}, counter: map[string]int{}, recs: map[string]*Replacement{}}
}

func (s *MappingStore) consistent(kind, original, prefix, mode, static string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := original
	if kind == "ipv4" || kind == "ipv6" || kind == "mac" {
		key = strings.ToLower(original)
	}
	token := static
	if !strings.EqualFold(mode, "static") {
		table, ok := s.maps[kind]
		if !ok {
			table = map[string]string{}
			s.maps[kind] = table
		}
		if t, ok := table[key]; ok {
			token = t
		} else {
			s.counter[kind]++
			token = fmt.Sprintf("x-%s-%010d-x", prefix, s.counter[kind])
			table[key] = token
		}
	}
	rk := kind + "|" + key
	rec, ok := s.recs[rk]
	if !ok {
		rec = &Replacement{Canonical: key, ReplacedWith: token, occ: map[string]int{}}
		s.recs[rk] = rec
	}
	rec.occ[original]++
	return token
}

func (s *MappingStore) Report() []Replacement {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Replacement, 0, len(s.recs))
	for _, rec := range s.recs {
		occ := make([]Occurrence, 0, len(rec.occ))
		for k, v := range rec.occ {
			occ = append(occ, Occurrence{Original: k, Count: v})
		}
		sort.Slice(occ, func(i, j int) bool { return occ[i].Original < occ[j].Original })
		out = append(out, Replacement{Canonical: rec.Canonical, ReplacedWith: rec.ReplacedWith, Occurrences: occ})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReplacedWith < out[j].ReplacedWith })
	return out
}

type Cleaner struct {
	cfg                                            Config
	Store                                          *MappingStore
	Omitted                                        []string
	Processed                                      int
	mu                                             sync.Mutex
	custom                                         []*regexp.Regexp
	customRepl                                     []string
	keywords, pathKeywords                         [][2]string
	domains                                        []string
	ipMode, macMode, domainMode, emailMode         string
	enableIP, enableMAC, enableDomain, enableEmail bool
	enableSecrets, enablePEM                       bool
	secrets                                        []secretPat
}

func NewCleaner(cfg Config, secrets []secretPat) *Cleaner {
	c := &Cleaner{cfg: cfg, Store: NewMappingStore(), ipMode: "Consistent", macMode: "Consistent", domainMode: "Consistent", emailMode: "Consistent", enableSecrets: true, enablePEM: true, secrets: secrets}
	if c.secrets == nil {
		c.secrets = defaultSecrets
	}
	for _, rule := range cfg.Obfuscate {
		t := strings.ToLower(rule.Type)
		mode := rule.ReplacementType
		if mode == "" {
			mode = "Consistent"
		}
		switch t {
		case "ip":
			c.enableIP, c.ipMode = true, mode
		case "mac":
			c.enableMAC, c.macMode = true, mode
		case "domain":
			c.enableDomain, c.domainMode = true, mode
			c.domains = append(c.domains, rule.DomainNames...)
		case "email":
			c.enableEmail, c.emailMode = true, mode
		case "keywords":
			pairs := sortedPairs(rule.Replacement)
			if strings.EqualFold(rule.Target, "FilePath") {
				c.pathKeywords = append(c.pathKeywords, pairs...)
			} else {
				c.keywords = append(c.keywords, pairs...)
			}
		case "regex":
			pat := rule.Regex
			if pat == "" {
				pat = rule.Pattern
			}
			if pat != "" {
				if re, err := regexp.Compile(pat); err == nil {
					repl := "x-redacted-regex-x"
					if rule.Replace != "" {
						repl = rule.Replace
					}
					c.custom = append(c.custom, re)
					c.customRepl = append(c.customRepl, repl)
				}
			}
		case "secrets", "secret":
			if rule.Enabled != nil {
				c.enableSecrets = *rule.Enabled
			}
		case "pem":
			if rule.Enabled != nil {
				c.enablePEM = *rule.Enabled
			}
		}
	}
	return c
}

func sortedPairs(m map[string]string) [][2]string {
	out := make([][2]string, 0, len(m))
	for k, v := range m {
		out = append(out, [2]string{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i][0]) > len(out[j][0]) })
	return out
}

func matchGlob(rel, pattern string) bool {
	rel = strings.TrimPrefix(strings.ReplaceAll(rel, "\\", "/"), "./")
	pat := strings.ReplaceAll(pattern, "\\", "/")
	cands := []string{rel, path.Base(rel)}
	pats := []string{pat, strings.TrimPrefix(pat, "./")}
	if strings.HasPrefix(pat, "**/") {
		pats = append(pats, pat[3:], "*/"+pat[3:])
	}
	for _, value := range cands {
		for _, p := range pats {
			if ok, _ := filepath.Match(p, value); ok {
				return true
			}
			p2 := strings.ReplaceAll(strings.ReplaceAll(p, "**/", "*"), "**", "*")
			if ok, _ := filepath.Match(p2, value); ok {
				return true
			}
			if ok, _ := path.Match(p2, value); ok {
				return true
			}
		}
	}
	return false
}

func (c *Cleaner) ShouldOmit(rel string) bool {
	for _, rule := range c.cfg.Omit {
		switch strings.ToLower(rule.Type) {
		case "file", "path":
			pat := rule.Pattern
			if pat == "" {
				pat = rule.Path
			}
			if pat != "" && matchGlob(rel, pat) {
				return true
			}
		case "extension":
			if rule.Extension != "" && strings.EqualFold(filepath.Ext(rel), rule.Extension) {
				return true
			}
		}
	}
	return false
}

func (c *Cleaner) ObfuscatePath(rel string) string {
	out := rel
	for _, kv := range c.pathKeywords {
		out = strings.ReplaceAll(out, kv[0], kv[1])
	}
	if c.enableIP {
		out = replaceIPv4(out, c.replIP)
	}
	return out
}

func (c *Cleaner) replIP(v string) string {
	if _, ok := localIPv4[v]; ok {
		return v
	}
	return c.Store.consistent("ipv4", v, "ipv4", c.ipMode, "x.x.x.x")
}

func (c *Cleaner) replIPv6(v string) string {
	if _, ok := localIPv6[strings.ToLower(v)]; ok {
		return v
	}
	return c.Store.consistent("ipv6", v, "ipv6", c.ipMode, "x:x:x:x:x:x:x:x")
}

func (c *Cleaner) ObfuscateText(text string) string {
	if c.enablePEM {
		text = pemRe.ReplaceAllString(text, "-----BEGIN REDACTED-----\nx-redacted-pem-x\n-----END REDACTED-----")
	}
	for _, kv := range c.keywords {
		if kv[0] != "" {
			text = strings.ReplaceAll(text, kv[0], kv[1])
		}
	}
	for i, re := range c.custom {
		text = re.ReplaceAllString(text, c.customRepl[i])
	}
	if c.enableSecrets {
		for _, s := range c.secrets {
			text = s.re.ReplaceAllString(text, s.repl)
		}
	}
	if c.enableEmail {
		text = emailRe.ReplaceAllStringFunc(text, func(v string) string {
			return c.Store.consistent("email", v, "email", c.emailMode, "redacted@example.invalid")
		})
	}
	if c.enableMAC {
		text = macRe.ReplaceAllStringFunc(text, func(v string) string {
			return c.Store.consistent("mac", v, "mac", c.macMode, "xx:xx:xx:xx:xx:xx")
		})
	}
	if c.enableDomain {
		sort.Slice(c.domains, func(i, j int) bool { return len(c.domains[i]) > len(c.domains[j]) })
		for _, d := range c.domains {
			token := c.Store.consistent("domain", strings.ToLower(d), "domain", c.domainMode, "redacted.example.invalid")
			text = regexp.MustCompile("(?i)"+regexp.QuoteMeta(d)).ReplaceAllString(text, token)
		}
	}
	if c.enableIP {
		text = replaceIPv4(text, c.replIP)
		text = ipv6Re.ReplaceAllStringFunc(text, c.replIPv6)
	}
	return text
}

func replaceIPv4(text string, fn func(string) string) string {
	return ipv4OnlyRe.ReplaceAllStringFunc(text, fn)
}

func (c *Cleaner) AddOmitted(rel string) {
	c.mu.Lock()
	c.Omitted = append(c.Omitted, rel)
	c.mu.Unlock()
}

func (c *Cleaner) AddProcessed() {
	c.mu.Lock()
	c.Processed++
	c.mu.Unlock()
}
