package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/vultisig/mobile-tss-lib/coordinator"
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
				Value:   "http://127.0.0.1:9090",
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
			&cli.BoolFlag{
				Name:       "leader",
				Usage:      "leader will make sure all parties present , and kick off the process(keygen/reshare/keysign)",
				Required:   false,
				Hidden:     false,
				HasBeenSet: false,
				Value:      false,
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
				Action: keygenCmd,
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
			{
				Name: "signECDSA",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:       "pubkey",
						Aliases:    []string{"pk"},
						Usage:      "ECDSA pubkey that will be used to do keysign",
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
				Action: keysignECDSACmd,
			},
			{
				Name: "signEDDSA",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:       "pubkey",
						Aliases:    []string{"pk"},
						Usage:      "EDDSA pubkey that will be used to do keysign",
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

func keygenCmd(c *cli.Context) error {
	key := c.String("key")
	parties := c.StringSlice("parties")
	session := c.String("session")
	server := c.String("server")
	chaincode := c.String("chaincode")
	isLeader := c.Bool("leader")
	fmt.Println("keygen", key, parties, session, server, chaincode)
	if isLeader {
		fmt.Println("I am the leader , start to wait for all parties to join")
		go func() {
			if coordinator.WaitAllParties(parties, server, session) != nil {
				fmt.Println("failed to wait for all parties to join")
				return
			}
			fmt.Println("all parties joined")
			if err := coordinator.StartSession(server, session, parties); err != nil {
				fmt.Println("failed to start session", err)
			}
		}()
	}
	_, err := coordinator.ExecuteKeyGeneration(coordinator.KeygenInput{
		Key:       key,
		Session:   session,
		Server:    server,
		ChainCode: chaincode,
	})
	if err != nil {
		return err
	}

	return nil
}

func reshareCmd(c *cli.Context) error {
	key := c.String("key")
	session := c.String("session")
	server := c.String("server")
	chaincode := c.String("chaincode")
	pubKey := c.String("pubkey")
	pubkeyEdDSA := c.String("pubkey-eddsa")
	oldParties := c.StringSlice("old-parties")
	resharePrefix := c.String("reshareprefix")

	_, err := coordinator.ExecuteKeyResharing(coordinator.ReshareInput{
		Key:           key,
		Session:       session,
		Server:        server,
		ChainCode:     chaincode,
		PubKey:        pubKey,
		PubKeyEdDSA:   pubkeyEdDSA,
		OldParties:    oldParties,
		ResharePrefix: resharePrefix,
	})

	if err != nil {
		return err
	}

	return nil
}

func keysignECDSACmd(c *cli.Context) error {
	key := c.String("key")
	session := c.String("session")
	server := c.String("server")
	pubkey := c.String("pubkey")
	message := c.String("message")
	derivePath := c.String("derivepath")

	_, err := coordinator.ExecuteECDSAKeySigning(coordinator.SignInput{
		Key:        key,
		Session:    session,
		Server:     server,
		PubKey:     pubkey,
		Message:    message,
		DerivePath: derivePath,
	})

	if err != nil {
		return err
	}

	return nil
}

func keysignEDDSACmd(c *cli.Context) error {
	key := c.String("key")
	session := c.String("session")
	server := c.String("server")
	pubkey := c.String("pubkey")
	message := c.String("message")

	_, err := coordinator.ExecuteEdDSAKeySigning(coordinator.SignInput{
		Key:     key,
		Session: session,
		Server:  server,
		PubKey:  pubkey,
		Message: message,
	})

	if err != nil {
		return err
	}

	return nil
}
