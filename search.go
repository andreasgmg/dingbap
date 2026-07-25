package main

import (
	"net/http"
	"strings"
	"unicode/utf8"
)

const (
	searchMaxQueryLen = 200
	searchMaxResults  = 100
)

type searchHit struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size,omitempty"`
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "query": q, "results": []searchHit{}})
		return
	}
	if utf8.RuneCountInString(q) > searchMaxQueryLen {
		jsonErr(w, http.StatusBadRequest, "Query too long")
		return
	}

	needle := strings.ToLower(q)
	results, limited := searchInTree(needle, searchMaxResults)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"query":   q,
		"results": results,
		"limited": limited,
	})
}

// searchInTree matches names against the in-memory directory listing cache.
// Cache misses load a single directory via listDirNodes (same path as /api/tree),
// so after the archive has been browsed — or after one search pass — subsequent
// queries are pure RAM scans with no filepath.Walk / bulk disk I/O.
func searchInTree(needle string, limit int) ([]searchHit, bool) {
	results := make([]searchHit, 0, 32)
	queue := []string{""}

	for len(queue) > 0 && len(results) < limit {
		rel := queue[0]
		queue = queue[1:]

		nodes, _, err := listDirNodes(rel)
		if err != nil {
			continue
		}
		for _, n := range nodes {
			if n.IsDir {
				queue = append(queue, n.Path)
			}
			if !strings.Contains(strings.ToLower(n.Name), needle) {
				continue
			}
			hit := searchHit{
				Name:  n.Name,
				Path:  n.Path,
				IsDir: n.IsDir,
			}
			if !n.IsDir {
				hit.Size = n.Size
			}
			results = append(results, hit)
			if len(results) >= limit {
				return results, true
			}
		}
	}
	return results, false
}
