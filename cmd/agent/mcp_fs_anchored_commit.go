package main

func receiveThenCommitUnderPathLock(path string, receive func() error, commit func() error) error {
	if err := receive(); err != nil {
		return err
	}
	unlock := fsPathMu.lock(path)
	defer unlock()
	return commit()
}
