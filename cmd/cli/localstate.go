package main

// type LocalStateAccessorImp struct {
// 	key string
// }

// func (l *LocalStateAccessorImp) GetLocalState(pubKey string) (string, error) {
// 	fileName := pubKey + "-" + l.key + ".json"
// 	if _, err := os.Stat(fileName); os.IsNotExist(err) {
// 		return "", fmt.Errorf("file %s does not exist", pubKey)
// 	}
// 	buf, err := os.ReadFile(fileName)
// 	if err != nil {
// 		return "", fmt.Errorf("fail to read file %s: %w", fileName, err)
// 	}
// 	return string(buf), nil
// }

// func (l *LocalStateAccessorImp) SaveLocalState(pubKey, localState string) error {
// 	fileName := pubKey + "-" + l.key + ".json"
// 	return os.WriteFile(fileName, []byte(localState), 0644)
// }
