package massa

import (
	"fmt"
	"os"
)

func dirExists(path string) (bool, error) {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed stating path: %w", err)
	}

	if !fi.IsDir() {
		return false, fmt.Errorf("'%s' exists but is not a dir", fi.Name())
	}

	return true, nil
}

func fileExists(path string) (bool, error) {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed stating path: %w", err)
	}

	if fi.IsDir() {
		return false, fmt.Errorf("'%s' exists but is a dir", fi.Name())
	}

	return true, nil
}
