package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/voltix-vault/mobile-tss-lib/tss"
	coordinator "github.com/voltix-vault/mobile-tss-lib/coordinator"
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
				Name: "keygen",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:       "chaincode",
						Aliases:    []string{"cc"},
						Usage:      "hex encoded chain code",
						Required:   true,
						HasBeenSet: false,
						Hidden:     false,
					},
				},
				Action: runCmd,
			},
			{
				Name: "reshare",
				Flags: []cli.Flag{
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
					},
				},
				Action: reshareCmd,
			},
			// {
			// 	Name:   "chaincode",
			// 	Action: generateChainCode,
			// },
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
					&cli.StringFlag{
						Name:     "derivepath",
						Usage:    "derive path for bitcoin, e.g. m/84'/0'/0'/0/0",
						Required: true,
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

func runCmd(c *cli.Context) error {
	key := c.String("key")
	parties := c.StringSlice("parties")
	session := c.String("session")
	server := c.String("server")
	chaincode := c.String("chaincode")

	keysign, err := ExecuteKeyGeneration()
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

}

func keysignCmd(c *cli.Context) error {
	key := c.String("key")
	parties := c.StringSlice("parties")
	session := c.String("session")
	server := c.String("server")
	pubkey := c.String("pubkey")
	message := c.String("message")
	derivePath := c.String("derivepath")

}

func keysignEDDSACmd(c *cli.Context) error {
	key := c.String("key")
	parties := c.StringSlice("parties")
	session := c.String("session")
	server := c.String("server")
	pubkey := c.String("pubkey")
	message := c.String("message")

}
