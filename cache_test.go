package main

import "testing"

func TestListingCache(t *testing.T) {
	dirCache.invalidate()
	nodes := []treeNode{{Name: "a.txt", Path: "a.txt", IsDir: false, Size: 3}}
	dirCache.set("", nodes)
	got, ok := dirCache.get("")
	if !ok || len(got) != 1 || got[0].Name != "a.txt" {
		t.Fatalf("%v %v", ok, got)
	}
	// mutation isolation
	got[0].Name = "mutated"
	got2, _ := dirCache.get("")
	if got2[0].Name != "a.txt" {
		t.Fatal("cache entry mutated")
	}
	invalidateListingCache()
	if _, ok := dirCache.get(""); ok {
		t.Fatal("expected empty after invalidate")
	}
}

func TestListingCacheLRUEviction(t *testing.T) {
	c := newListingCache(3)
	c.set("a", []treeNode{{Name: "a"}})
	c.set("b", []treeNode{{Name: "b"}})
	c.set("c", []treeNode{{Name: "c"}})
	// Touch a so b is the oldest when d is inserted.
	if _, ok := c.get("a"); !ok {
		t.Fatal("a missing")
	}
	c.set("d", []treeNode{{Name: "d"}})
	if c.len() != 3 {
		t.Fatalf("len=%d", c.len())
	}
	if _, ok := c.get("b"); ok {
		t.Fatal("expected b evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.get(k); !ok {
			t.Fatalf("expected %s present", k)
		}
	}
}
