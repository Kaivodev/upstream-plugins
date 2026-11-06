//go:build !wasip1

package sdk

import "errors"

func hostCall(string, []byte) ([]byte, error) { return nil, errors.New("SDK requires wasip1 host") }
