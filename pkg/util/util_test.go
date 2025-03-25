package util

import (
	"reflect"
	"testing"
)

func TestGenerateQueue(t *testing.T) {
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

	gq := func(start, size int) []int {
		result := make([]int, size)
		for i := range size {
			result[i] = RotateQueue1(start, i, size)
		}
		return result
	}

	for _, c := range cases {
		if !reflect.DeepEqual(c.want, gq(c.start, c.size)) {
			t.Errorf("generateQueue(%d, %d) == %d, want %d", c.start, c.size, gq(c.start, c.size), c.want)
		}
	}
}
