package clean

import (
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type Cleaner struct {
	cfg           Config
	Store         *MappingStore
	Omitted       []string
	Processed     int
	mu            sync.Mutex
	custom        []*regexp.Regexp
	customRepl    []string
	keywords      [][2]string
	pathKeywords  [][2]string
	domains       []string
	ipMode        string
	macMode       string
	domainMode    string
	emailMode     string
	enableIP      bool
	enableMAC     bool
	enableDomain  bool
	enableEmail   bool
	enableSecrets bool
	enablePEM     bool
	secrets       []secretPat
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
			c.enableIP = true
			c.ipMode = mode
		case "mac":
			c.enableMAC = true
			c.macMode = mode
		case "domain":
			c.enableDomain = true
			c.domainMode = mode
			c.domains = append(c.domains, rule.DomainNames...)
		case "email":
			c.enableEmail = true
			c.emailMode = mode
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
					c.custom = append(c.custom, re)
					c.customRepl = append(c.customRepl, firstRepl(rule))
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

func firstRepl(rule ObfuscateRule) string {
	if rule.Replace != "" {
		return rule.Replace
	}
	return "x-redacted-regex-x"
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
	rel = strings.ReplaceAll(rel, "\\", "/")
	rel = strings.TrimPrefix(rel, "./")
	pat := strings.ReplaceAll(pattern, "\\", "/")
	name := path.Base(rel)
	cands := []string{rel, name}
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
		t := strings.ToLower(rule.Type)
		switch t {
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
		out = replaceIPv4(out, func(v string) string { return c.replIP(v) })
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
			if !looksLikeEmail(v) {
				return v
			}
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
		text = replaceIPv4(text, func(v string) string { return c.replIP(v) })
		text = ipv6Re.ReplaceAllStringFunc(text, func(v string) string {
			if !looksLikeIPv6(v) {
				return v
			}
			return c.replIPv6(v)
		})
	}
	return text
}

func replaceIPv4(text string, fn func(string) string) string {
	return ipv4OnlyRe.ReplaceAllStringFunc(text, func(v string) string { return fn(v) })
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
