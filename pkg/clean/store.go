package clean

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

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
	return &MappingStore{
		maps:    map[string]map[string]string{},
		counter: map[string]int{},
		recs:    map[string]*Replacement{},
	}
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
