package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/voltix-vault/mobile-tss-lib/tss"
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
				if err := tssServerImp.ApplyData(message.Body); err != nil {
					log.Println("fail to apply data:", err)
				}
			}
		}
	}
}

func waitAllParties(parties []string, server, session string) error {
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
		if equalUnordered(keys, parties) {
			fmt.Println("all parties joined")
			return nil
		}

		fmt.Println("waiting for all parties to join...")

		// backoff
		time.Sleep(2 * time.Second)
	}
}

type MessengerImp struct {
	Server    string
	SessionID string
}

func (m *MessengerImp) Send(from, to, body string) error {
	buf, err := json.MarshalIndent(struct {
		SessionID string   `json:"session_id,omitempty"`
		From      string   `json:"from,omitempty"`
		To        []string `json:"to,omitempty"`
		Body      string   `json:"body,omitempty"`
	}{
		SessionID: m.SessionID,
		From:      from,
		To:        []string{to},
		Body:      body,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("fail to marshal message: %w", err)
	}
	log.Println("sending message:", string(buf))
	resp, err := http.Post(m.Server+"/message/"+m.SessionID, "application/json", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("fail to send message: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("fail to send message: %s", resp.Status)
	}

	return nil
}
