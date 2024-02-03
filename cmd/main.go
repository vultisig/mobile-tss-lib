package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/johnnyluo/mobile-tss-lib/tss"
	"github.com/urfave/cli/v2"
)

func main() {
	app := cli.App{
		Name:  "tss-test",
		Usage: "tss-test is a tool for testing tss library.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "server",
				Aliases: []string{"s"},
				Usage:   "server address",
				Value:   "http://127.0.0.1:8080",
			},
			&cli.StringFlag{
				Name:       "key",
				Aliases:    []string{"k"},
				Usage:      "something to uniquely identify local party",
				Required:   true,
				HasBeenSet: false,
				Hidden:     false,
			},
			&cli.StringSliceFlag{
				Name:       "parties",
				Aliases:    []string{"p"},
				Usage:      "comma separated list of party keys, need to have all the keys of the keygen committee",
				Required:   true,
				HasBeenSet: false,
				Hidden:     false,
			},
			&cli.StringFlag{
				Name:       "session",
				Usage:      "current communication session",
				Required:   true,
				HasBeenSet: false,
				Hidden:     false,
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "keygen",
				Flags:  []cli.Flag{},
				Action: runCmd,
			},
			{
				Name: "sign",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:       "pubkey",
						Aliases:    []string{"pk"},
						Usage:      "pubkey that will be used to do keysign",
						Required:   true,
						HasBeenSet: false,
						Hidden:     false,
					},
					&cli.StringFlag{
						Name:       "message",
						Aliases:    []string{"m"},
						Usage:      "message that need to be signed",
						Required:   true,
						HasBeenSet: false,
						Hidden:     false,
					},
				},
				Action: keysignCmd,
			},
			{
				Name: "signEDDSA",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:       "pubkey",
						Aliases:    []string{"pk"},
						Usage:      "pubkey that will be used to do keysign",
						Required:   true,
						HasBeenSet: false,
						Hidden:     false,
					},
					&cli.StringFlag{
						Name:       "message",
						Aliases:    []string{"m"},
						Usage:      "message that need to be signed",
						Required:   true,
						HasBeenSet: false,
						Hidden:     false,
					},
				},
				Action: keysignEDDSACmd,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
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

type LocalStateAccessorImp struct {
	key string
}

func (l *LocalStateAccessorImp) GetLocalState(pubKey string) (string, error) {
	fileName := pubKey + "-" + l.key + ".json"
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return "", fmt.Errorf("file %s does not exist", pubKey)
	}
	buf, err := os.ReadFile(fileName)
	if err != nil {
		return "", fmt.Errorf("fail to read file %s: %w", fileName, err)
	}
	return string(buf), nil
}
func (l *LocalStateAccessorImp) SaveLocalState(pubKey, localState string) error {
	fileName := pubKey + "-" + l.key + ".json"
	return os.WriteFile(fileName, []byte(localState), 0644)
}

func runCmd(c *cli.Context) error {
	key := c.String("key")
	parties := c.StringSlice("parties")
	session := c.String("session")
	server := c.String("server")
	if err := registerSession(server, session, key); err != nil {
		return fmt.Errorf("fail to register session: %w", err)
	}
	if err := waitAllParties(parties, server, session); err != nil {
		return fmt.Errorf("fail to wait all parties: %w", err)
	}
	messenger := &MessengerImp{
		Server:    server,
		SessionID: session,
	}
	localStateAccessor := &LocalStateAccessorImp{
		key: key,
	}
	tssServerImp, err := tss.NewService(messenger, localStateAccessor)
	if err != nil {
		return fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(server, session, key, tssServerImp, endCh, wg)
	log.Println("start ECDSA keygen...")
	resp, err := tssServerImp.KeygenECDSA(&tss.KeygenRequest{
		LocalPartyID: key,
		AllParties:   strings.Join(parties, ","),
	})
	if err != nil {
		return fmt.Errorf("fail to generate ECDSA key: %w", err)
	}
	log.Printf("ECDSA keygen response: %+v\n", resp)

	log.Println("start EDDSA keygen...")
	respEDDSA, errEDDSA := tssServerImp.KeygenEDDSA(&tss.KeygenRequest{
		LocalPartyID: key,
		AllParties:   strings.Join(parties, ","),
	})
	if errEDDSA != nil {
		return fmt.Errorf("fail to generate EDDSA key: %w", errEDDSA)
	}
	log.Printf("EDDSA keygen response: %+v\n", respEDDSA)
	if err := endSession(server, session, key); err != nil {
		log.Printf("fail to end session: %s\n", err)
	}
	close(endCh)
	wg.Wait()
	return nil
}
func waitAllParties(parties []string, server, session string) error {
	sessionUrl := server + "/" + session
	for {
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
			return nil
		}
		// backoff
		time.Sleep(2 * time.Second)
	}
}

func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	amap := make(map[string]int)
	for _, val := range a {
		amap[val]++
	}

	for _, val := range b {
		if amap[val] == 0 {
			return false
		}
		amap[val]--
	}

	return true
}

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

func endSession(server, session, key string) error {
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

func keysignCmd(c *cli.Context) error {
	key := c.String("key")
	parties := c.StringSlice("parties")
	session := c.String("session")
	server := c.String("server")
	pubkey := c.String("pubkey")
	message := c.String("message")

	if err := registerSession(server, session, key); err != nil {
		return fmt.Errorf("fail to register session: %w", err)
	}
	if err := waitAllParties(parties, server, session); err != nil {
		return fmt.Errorf("fail to wait all parties: %w", err)
	}
	messenger := &MessengerImp{
		Server:    server,
		SessionID: session,
	}
	localStateAccessor := &LocalStateAccessorImp{
		key: key,
	}
	tssServerImp, err := tss.NewService(messenger, localStateAccessor)
	if err != nil {
		return fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(server, session, key, tssServerImp, endCh, wg)
	log.Println("start ECDSA keysign...")
	resp, err := tssServerImp.KeysignECDSA(&tss.KeysignRequest{
		PubKey:               pubkey,
		MessageToSign:        message,
		LocalPartyKey:        key,
		KeysignCommitteeKeys: strings.Join(parties, ","),
	})
	if err != nil {
		return fmt.Errorf("fail to ECDSA key sign: %w", err)
	}
	log.Printf("ECDSA keysign response: %+v\n", resp)
	// delay one second before clean up the session
	time.Sleep(time.Second)
	if err := endSession(server, session, key); err != nil {
		log.Printf("fail to end session: %s\n", err)
	}
	close(endCh)
	wg.Wait()
	return nil
}

func keysignEDDSACmd(c *cli.Context) error {
	key := c.String("key")
	parties := c.StringSlice("parties")
	session := c.String("session")
	server := c.String("server")
	pubkey := c.String("pubkey")
	message := c.String("message")

	if err := registerSession(server, session, key); err != nil {
		return fmt.Errorf("fail to register session: %w", err)
	}
	if err := waitAllParties(parties, server, session); err != nil {
		return fmt.Errorf("fail to wait all parties: %w", err)
	}
	messenger := &MessengerImp{
		Server:    server,
		SessionID: session,
	}
	localStateAccessor := &LocalStateAccessorImp{
		key: key,
	}
	tssServerImp, err := tss.NewService(messenger, localStateAccessor)
	if err != nil {
		return fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(server, session, key, tssServerImp, endCh, wg)
	log.Println("start EDDSA keysign...")
	resp, err := tssServerImp.KeysignEDDSA(&tss.KeysignRequest{
		PubKey:               pubkey,
		MessageToSign:        message,
		LocalPartyKey:        key,
		KeysignCommitteeKeys: strings.Join(parties, ","),
	})
	if err != nil {
		return fmt.Errorf("fail to EDDSA key sign: %w", err)
	}
	log.Printf("EDDSA keysign response: %+v\n", resp)

	// delay one second before clean up the session
	time.Sleep(time.Second)
	if err := endSession(server, session, key); err != nil {
		log.Printf("fail to end session: %s\n", err)
	}
	close(endCh)
	wg.Wait()
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
			messages := []struct {
				SessionID string   `json:"session_id,omitempty"`
				From      string   `json:"from,omitempty"`
				To        []string `json:"to,omitempty"`
				Body      string   `json:"body,omitempty"`
			}{}
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
