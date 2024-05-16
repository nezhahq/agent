package main

import (
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
