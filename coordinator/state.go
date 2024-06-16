package coordinator

import (
	"fmt"
	"os"
	"path/filepath"
)

type LocalStateAccessorImp struct {
	Key    string
	Folder string
}

func (l *LocalStateAccessorImp) ensureFolder() error {
	if l.Folder == "" {
		var err error
		l.Folder, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
	}
	return nil
}

func (l *LocalStateAccessorImp) GetLocalState(pubKey string) (string, error) {
	if err := l.ensureFolder(); err != nil {
		return "", err
	}
	fileName := filepath.Join(l.Folder, pubKey+"-"+l.Key+".json")
	fmt.Println(fileName)
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return "", fmt.Errorf("file %s does not exist", fileName)
	}
	buf, err := os.ReadFile(fileName)
	if err != nil {
		return "", fmt.Errorf("fail to read file %s: %w", fileName, err)
	}
	// fmt.Println(string(buf))
	return string(buf), nil
}

func (l *LocalStateAccessorImp) SaveLocalState(pubKey, localState string) error {
	if err := l.ensureFolder(); err != nil {
		return err
	}
	fileName := filepath.Join(l.Folder, pubKey+"-"+l.Key+".json")
	return os.WriteFile(fileName, []byte(localState), 0644)
}
