package coordinator

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/vultisig/mobile-tss-lib/tss"
)

func registerSession(server, session, key string) error {
	sessionUrl := server + "/" + session
	fmt.Println("Registering session with url: ", sessionUrl)
	body := []byte("[\"" + key + "\"]")
	fmt.Println("Registering session with body: ", string(body))
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
	// fmt.Println(sessionUrl)

	body, err := json.Marshal(parties)
	if err != nil {
		return fmt.Errorf("fail to start session: %w", err)
	}
	bodyReader := bytes.NewReader(body)
	client := http.Client{}
	req, err := http.NewRequest(http.MethodPost, sessionUrl, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return fmt.Errorf("fail to start session: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fail to start session: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fail to start session: %s", resp.Status)
	}
	return nil
}

func EndSession(server, session string) error {
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

func DownloadMessage(server, session, key string, tssServerImp tss.Service, endCh chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-endCh: // we are done
			return
		case <-time.After(time.Second):
			resp, err := http.Get(server + "/message/" + session + "/" + key)
			if err != nil {
				log.Println("fail to get data from server:", err)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				log.Println("fail to get data from server:", resp.Status)
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
					log.Println("fail to decode messages:", err)
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
					log.Println("fail to delete message:", err)
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					log.Println("fail to delete message:", err)
					continue
				}
				if resp.StatusCode != http.StatusOK {
					log.Println("fail to delete message:", resp.Status)
					continue
				}

				if err := tssServerImp.ApplyData(message.Body); err != nil {
					log.Println("fail to apply data:", err)
				}

			}
		}
	}
}

func WaitAllParties(parties []string, server, session string) error {
	sessionUrl := server + "/" + session
	for {
		fmt.Println("start waiting for all parties to join...")
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
		if EqualUnordered(keys, parties) {
			fmt.Println("all parties joined")
			return nil
		}

		fmt.Println("waiting for all parties to join...")

		// backoff
		time.Sleep(2 * time.Second)
	}
}

func WaitForSessionStart(server, session string) ([]string, error) {
	sessionUrl := server + "/start/" + session
	// fmt.Println(sessionUrl)
	for {
		fmt.Println("start waiting for someone to start session...")
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
		// print parties
		fmt.Println("parties:", parties)
		if len(parties) > 1 {
			fmt.Println("all parties joined")
			return parties, nil
		}

		fmt.Println("waiting for someone to start session...")

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
	defer resp.Body.Close()

	if resp.Status != "202 Accepted" {
		return fmt.Errorf("fail to send message, response code is not 202 Accepted: %s", resp.Status)
	}

	fmt.Println("message sent")

	return nil
}
