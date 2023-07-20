//go:build !linux

package libv2ray

import (
	"errors"
)

func NewTun2ray(config *TunConfig) (*Tun2ray, error) {
	return nil, errors.New("unsupported")
}
