package main

import (
	"fmt"
	"reflect"
	"testing"
)

func Test(t *testing.T) {
	cases := []struct {
		start, size int
		want        []int
	}{
		{0, 2, []int{0, 1}},
		{1, 2, []int{1, 0}},
		{0, 3, []int{0, 1, 2}},
		{1, 3, []int{1, 2, 0}},
		{2, 3, []int{2, 0, 1}},
	}

	for _, c := range cases {
		if !reflect.DeepEqual(c.want, generateQueue(c.start, c.size)) {
			t.Errorf("generateQueue(%d, %d) == %d, want %d", c.start, c.size, generateQueue(c.start, c.size), c.want)
		}
	}
}

func TestLookupIP(t *testing.T) {
	ip, err := lookupIP("www.google.com")
	fmt.Printf("ip: %v, err: %v\n", ip, err)
	if err != nil {
		t.Errorf("lookupIP failed: %v", err)
	}
}
