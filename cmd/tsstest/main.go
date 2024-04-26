package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/urfave/cli/v2"

	"github.com/voltix-vault/mobile-tss-lib/tss"
)

func commonFlags() []cli.Flag {
	return []cli.Flag{
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
	}
}
func main() {
	app := cli.App{
		Name:  "tss-test",
		Usage: "tss-test is a tool for testing tss library.",
		Commands: []*cli.Command{
			{
				Name: "keygen",
				Flags: append(commonFlags(),
					&cli.StringFlag{
						Name:       "chaincode",
						Aliases:    []string{"cc"},
						Usage:      "hex encoded chain code",
						Required:   true,
						HasBeenSet: false,
						Hidden:     false,
					}),
				Action: runCmd,
			},
			{
				Name: "reshare",
				Flags: append(commonFlags(),
					&cli.StringFlag{
						Name:       "chaincode",
						Aliases:    []string{"cc"},
						Usage:      "hex encoded chain code",
						Required:   true,
						HasBeenSet: false,
						Hidden:     false,
					},
					&cli.StringSliceFlag{
						Name:       "old-parties",
						Usage:      "comma separated list of party keys, need to have all the keys of the keygen committee",
						Required:   true,
						HasBeenSet: false,
						Hidden:     false,
					},
					&cli.StringFlag{
						Name:       "pubkey",
						Aliases:    []string{"pk"},
						Usage:      "pubkey that will be used to do resharing",
						Required:   false,
						HasBeenSet: false,
						Hidden:     false,
					},
					&cli.StringFlag{
						Name:       "pubkey-eddsa",
						Usage:      "pubkey that will be used to do resharing",
						Required:   false,
						HasBeenSet: false,
						Hidden:     false,
					},
					&cli.StringFlag{
						Name:       "reshareprefix",
						Usage:      "reshare prefix",
						Required:   false,
						HasBeenSet: false,
						Hidden:     false,
					}),
				Action: reshareCmd,
			},
			{
				Name:   "chaincode",
				Action: generateChainCode,
				Flags:  commonFlags(),
			},
			{
				Name: "sign",
				Flags: append(commonFlags(),
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
					&cli.StringFlag{
						Name:     "derivepath",
						Usage:    "derive path for bitcoin, e.g. m/84'/0'/0'/0/0",
						Required: true,
					}),
				Action: keysignCmd,
			},
			{
				Name: "signEDDSA",
				Flags: append(commonFlags(),
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
					}),
				Action: keysignEDDSACmd,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
func fillBytes(x *big.Int, buf []byte) []byte {
	b := x.Bytes()
	if len(b) > len(buf) {
		panic("buffer too small")
	}
	offset := len(buf) - len(b)
	for i := range buf {
		if i < offset {
			buf[i] = 0
		} else {
			buf[i] = b[i-offset]
		}
	}
	return buf
}

func generateChainCode(*cli.Context) error {
	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	fillBytes(common.GetRandomPositiveInt(rand.Reader, max32b), chainCode)
	fmt.Println("chain code:", hex.EncodeToString(chainCode))
	return nil
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
	chaincode := c.String("chaincode")
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
	tssServerImp, err := tss.NewService(messenger, localStateAccessor, true)
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
		ChainCodeHex: chaincode,
	})
	if err != nil {
		return fmt.Errorf("fail to generate ECDSA key: %w", err)
	}
	log.Printf("ECDSA keygen response: %+v\n", resp)
	time.Sleep(time.Second)
	log.Println("start EDDSA keygen...")
	respEDDSA, errEDDSA := tssServerImp.KeygenEdDSA(&tss.KeygenRequest{
		LocalPartyID: key,
		AllParties:   strings.Join(parties, ","),
		ChainCodeHex: chaincode,
	})
	if errEDDSA != nil {
		return fmt.Errorf("fail to generate EDDSA key: %w", errEDDSA)
	}
	log.Printf("EDDSA keygen response: %+v\n", respEDDSA)
	time.Sleep(time.Second)
	if err := endSession(server, session); err != nil {
		log.Printf("fail to end session: %s\n", err)
	}
	close(endCh)
	wg.Wait()
	return nil
}

func reshareCmd(c *cli.Context) error {
	key := c.String("key")
	parties := c.StringSlice("parties")
	session := c.String("session")
	server := c.String("server")
	chaincode := c.String("chaincode")
	pubKey := c.String("pubkey")
	pubkeyEdDSA := c.String("pubkey-eddsa")
	oldParties := c.StringSlice("old-parties")
	resharePrefix := c.String("reshareprefix")
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
	tssServerImp, err := tss.NewService(messenger, localStateAccessor, true)
	if err != nil {
		return fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(server, session, key, tssServerImp, endCh, wg)
	log.Println("start ECDSA key resharing...")
	resp, err := tssServerImp.ReshareECDSA(&tss.ReshareRequest{
		PubKey:        pubKey,
		LocalPartyID:  key,
		NewParties:    strings.Join(parties, ","), // new parties
		OldParties:    strings.Join(oldParties, ","),
		ChainCodeHex:  chaincode,
		ResharePrefix: resharePrefix,
	})
	if err != nil {
		return fmt.Errorf("fail to reshare ECDSA key: %w", err)
	}
	log.Printf("ECDSA keygen response: %+v\n", resp)
	time.Sleep(time.Second)
	log.Println("start EDDSA keygen...")
	respEDDSA, errEdDSA := tssServerImp.ResharingEdDSA(&tss.ReshareRequest{
		PubKey:        pubkeyEdDSA,
		LocalPartyID:  key,
		NewParties:    strings.Join(parties, ","),
		OldParties:    strings.Join(oldParties, ","),
		ChainCodeHex:  chaincode,
		ResharePrefix: resharePrefix,
	})
	if errEdDSA != nil {
		return fmt.Errorf("fail to generate EDDSA key: %w", errEdDSA)
	}
	log.Printf("EDDSA keygen response: %+v\n", respEDDSA)
	time.Sleep(time.Second)
	if err := endSession(server, session); err != nil {
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

func keysignCmd(c *cli.Context) error {
	key := c.String("key")
	parties := c.StringSlice("parties")
	session := c.String("session")
	server := c.String("server")
	pubkey := c.String("pubkey")
	message := c.String("message")
	derivePath := c.String("derivepath")

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
	tssServerImp, err := tss.NewService(messenger, localStateAccessor, false)
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
		DerivePath:           derivePath,
	})

	rBytes, err := base64.RawStdEncoding.DecodeString(resp.R)
	if err != nil {
		return fmt.Errorf("fail to decode r: %w", err)
	}
	sBytes, err := base64.RawStdEncoding.DecodeString(resp.S)
	if err != nil {
		return fmt.Errorf("fail to decode s: %w", err)
	}
	signature := append(rBytes, sBytes...)
	log.Printf("ECDSA keysign signature: %s\n", base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		return fmt.Errorf("fail to ECDSA key sign: %w", err)
	}
	log.Printf("ECDSA keysign response: %+v\n", resp)
	// delay one second before clean up the session
	time.Sleep(time.Second)
	if err := endSession(server, session); err != nil {
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
	tssServerImp, err := tss.NewService(messenger, localStateAccessor, false)
	if err != nil {
		return fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(server, session, key, tssServerImp, endCh, wg)
	log.Println("start EDDSA keysign...")
	resp, err := tssServerImp.KeysignEdDSA(&tss.KeysignRequest{
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
	if err := endSession(server, session); err != nil {
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
