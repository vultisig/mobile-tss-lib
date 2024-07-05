package coordinator

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vultisig/mobile-tss-lib/tss"
)

func registerSession(server, session, key string) error {
	sessionUrl := server + "/" + session
	body := []byte("[\"" + key + "\"]")
	bodyReader := bytes.NewReader(body)
	resp, err := http.Post(sessionUrl, "application/json", bodyReader)
	if err != nil {
		return fmt.Errorf("fail to register session: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("fail to register session: %s", resp.Status)
	}
	return nil
}

func StartSession(server string, session string, parties []string) error {
	sessionUrl := server + "/start/" + session
	body, err := json.Marshal(parties)
	if err != nil {
		return fmt.Errorf("fail to start session: %w", err)
	}
	bodyReader := bytes.NewReader(body)
	client := http.Client{}
	req, err := http.NewRequest(http.MethodPost, sessionUrl, bodyReader)
	if err != nil {
		return fmt.Errorf("fail to start session: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fail to start session: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fail to start session: %s", resp.Status)
	}
	return nil
}

func endSession(server, session string) error {
	sessionUrl := server + "/" + session
	client := http.Client{}
	req, err := http.NewRequest(http.MethodDelete, sessionUrl, nil)
	if err != nil {
		return fmt.Errorf("fail to end session: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fail to end session: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fail to end session: %s", resp.Status)
	}
	return nil
}

func downloadMessage(server, session, key string, tssServerImp tss.Service, endCh chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-endCh: // we are done
			return
		case <-time.After(time.Second):
			resp, err := http.Get(server + "/message/" + session + "/" + key)
			if err != nil {
				log.Error("fail to get data from server", "error", err)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				log.Debug("fail to get data from server", "status", resp.Status)
				continue
			}
			decoder := json.NewDecoder(resp.Body)
			var messages []struct {
				SessionID string   `json:"session_id,omitempty"`
				From      string   `json:"from,omitempty"`
				To        []string `json:"to,omitempty"`
				Body      string   `json:"body,omitempty"`
			}
			if err := decoder.Decode(&messages); err != nil {
				if err != io.EOF {
					log.Error("fail to decode messages", "error", err)
				}
				continue
			}
			for _, message := range messages {
				if message.From == key {
					continue
				}

				hash := md5.Sum([]byte(message.Body))
				hashStr := hex.EncodeToString(hash[:])

				client := http.Client{}
				req, err := http.NewRequest(http.MethodDelete, server+"/message/"+session+"/"+key+"/"+hashStr, nil)
				if err != nil {
					log.Error("fail to delete message", "error", err)
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					log.Error("fail to delete message", "error", err)
					continue
				}
				if resp.StatusCode != http.StatusOK {
					log.Error("fail to delete message", "status", resp.Status)
					continue
				}

				if err := tssServerImp.ApplyData(message.Body); err != nil {
					log.Error("fail to apply data", "error", err)
				}

			}
		}
	}
}

func WaitAllParties(parties []string, server, session string) error {
	sessionUrl := server + "/" + session
	for {
		log.Debug("start waiting for all parties to join...")
		resp, err := http.Get(sessionUrl)
		if err != nil {
			return fmt.Errorf("fail to get session: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("fail to get session: %s", resp.Status)
		}
		var keys []string
		buff, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("fail to read session body: %w", err)
		}
		if err := json.Unmarshal(buff, &keys); err != nil {
			return fmt.Errorf("fail to unmarshal session body: %w", err)
		}
		if equalUnordered(keys, parties) {
			log.Debug("all parties joined")
			return nil
		}

		// backoff
		time.Sleep(2 * time.Second)
	}
}

func waitForSessionStart(server, session string) ([]string, error) {
	sessionUrl := server + "/start/" + session

	for {
		resp, err := http.Get(sessionUrl)
		if err != nil {
			return nil, fmt.Errorf("fail to get session: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fail to get session: %s", resp.Status)
		}
		var parties []string
		buff, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("fail to read session body: %w", err)
		}
		if err := json.Unmarshal(buff, &parties); err != nil {
			return nil, fmt.Errorf("fail to unmarshal session body: %w", err)
		}

		if len(parties) > 0 {
			return parties, nil
		}

		// backoff
		time.Sleep(2 * time.Second)
	}
}

type MessengerImp struct {
	Server    string
	SessionID string
}

func (m *MessengerImp) Send(from, to, body string) error {
	hash := md5.New()
	hash.Write([]byte(body))
	hashStr := hex.EncodeToString(hash.Sum(nil))

	if hashStr == "" {
		return fmt.Errorf("hash is empty")
	}

	buf, err := json.MarshalIndent(struct {
		SessionID string   `json:"session_id,omitempty"`
		From      string   `json:"from,omitempty"`
		To        []string `json:"to,omitempty"`
		Body      string   `json:"body,omitempty"`
		Hash      string   `json:"hash,omitempty"`
	}{
		SessionID: m.SessionID,
		From:      from,
		To:        []string{to},
		Body:      body,
		Hash:      hashStr,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("fail to marshal message: %w", err)
	}

	url := fmt.Sprintf("%s/message/%s", m.Server, m.SessionID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body == "" {
		return fmt.Errorf("body is empty")
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("fail to send message, response code is not 202 Accepted: %s", resp.Status)
	}
	log.Debug("message sent")
	return nil
}
