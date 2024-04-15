package service

import (
	"context"
)

type Zone interface {
	Collect(ctx context.Context, poolName string) ([]Pool, error)
}
