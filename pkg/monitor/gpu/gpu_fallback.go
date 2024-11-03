//go:build !darwin && !linux && !windows

package gpu

import "context"

func GetHost(_ context.Context) ([]string, error) {
	return nil, nil
}

func GetState(_ context.Context) ([]float64, error) {
	return nil, nil
}
