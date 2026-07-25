package main

import (
	"container/list"
	"strings"
	"sync"
)

const dirCacheMaxEntries = 1000

// listingCache holds recent directory listings in memory to avoid repeated ReadDir
// syscalls on hot paths. dingbap has no SQL database — users, sessions, shares,
// and trash metadata are already process-local; this caches filesystem listings.
// Eviction is LRU with a hard cap so deep searches cannot pin unbounded RAM.
type listingCache struct {
	mu  sync.Mutex
	m   map[string]*list.Element
	lru *list.List
	max int
}

type cacheItem struct {
	key   string
	nodes []treeNode
}

var dirCache = newListingCache(dirCacheMaxEntries)

func newListingCache(max int) *listingCache {
	if max < 1 {
		max = dirCacheMaxEntries
	}
	return &listingCache{
		m:   make(map[string]*list.Element),
		lru: list.New(),
		max: max,
	}
}

func cacheKey(rel string) string {
	return strings.Trim(rel, `/\`)
}

func (c *listingCache) get(rel string) ([]treeNode, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[cacheKey(rel)]
	if !ok {
		return nil, false
	}
	c.lru.MoveToFront(el)
	item := el.Value.(*cacheItem)
	out := make([]treeNode, len(item.nodes))
	copy(out, item.nodes)
	return out, true
}

func (c *listingCache) set(rel string, nodes []treeNode) {
	cp := make([]treeNode, len(nodes))
	copy(cp, nodes)

	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey(rel)
	if el, ok := c.m[key]; ok {
		el.Value.(*cacheItem).nodes = cp
		c.lru.MoveToFront(el)
		return
	}
	el := c.lru.PushFront(&cacheItem{key: key, nodes: cp})
	c.m[key] = el
	for c.lru.Len() > c.max {
		back := c.lru.Back()
		if back == nil {
			break
		}
		item := c.lru.Remove(back).(*cacheItem)
		delete(c.m, item.key)
	}
}

func (c *listingCache) invalidate() {
	c.mu.Lock()
	c.m = make(map[string]*list.Element)
	c.lru.Init()
	c.mu.Unlock()
}

func (c *listingCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

func invalidateListingCache() {
	dirCache.invalidate()
}
