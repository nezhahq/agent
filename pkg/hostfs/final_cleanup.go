package hostfs

import "errors"

func joinFinalCleanup(primaryErr error, closeNative func() error) error {
	return errors.Join(primaryErr, closeNative())
}
