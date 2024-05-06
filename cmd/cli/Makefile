.PHONY: all keygen keysign reshare clean

# Common variables
CHAINCODE = 80871c0f885f953e5206e461630a9222148797e66276a83224c7b9b0f75b3ec0
PUBKEY = 020c0de41f4b57e64bfab9387a095d72b1f2c835c8083ae61e45a3d2de2dccda77
PUBKEY_EDDSA = 89be02053f561f822c1939de63455ea94d1991dd013abdc5451b69cc3e4f9847
MESSAGE = aGVsbG8gd29ybGQK
DERIVEPATH = "m/84'/0'/0'/0/0"
SESSION := $(shell echo $$RANDOM)

all: keygen keysign reshare

keygen:
	trap 'kill $$PID_LIST' SIGINT; \
	go run main.go --key first --parties first,second,third --session $(SESSION) keygen --chaincode $(CHAINCODE) & PID_LIST=$$!; \
	go run main.go --key second --parties first,second,third --session $(SESSION) keygen --chaincode $(CHAINCODE) & PID_LIST="$$PID_LIST $$!"; \
	go run main.go --key third --parties first,second,third --session $(SESSION) keygen --chaincode $(CHAINCODE) & PID_LIST="$$PID_LIST $$!"; \
	wait $$PID_LIST

keysign:
	trap 'kill $$PID_LIST' SIGINT; \
	go run main.go --key first --parties first,second --session $(SESSION) signECDSA --pubkey $(PUBKEY) --message $(MESSAGE) --derivepath $(DERIVEPATH) & PID_LIST=$$!; \
	go run main.go --key second --parties first,second --session $(SESSION) signECDSA --pubkey $(PUBKEY) --message $(MESSAGE) --derivepath $(DERIVEPATH) & PID_LIST="$$PID_LIST $$!"; \
	wait $$PID_LIST

reshare:
	trap 'kill $$PID_LIST' SIGINT; \
	go run main.go --key first --parties first,second,third,fourth --session $(SESSION) reshare --chaincode $(CHAINCODE) --old-parties first,second,third --pubkey $(PUBKEY) --pubkey-eddsa $(PUBKEY_EDDSA) & PID_LIST=$$!; \
	go run main.go --key second --parties first,second,third,fourth --session $(SESSION) reshare --chaincode $(CHAINCODE) --old-parties first,second,third --pubkey $(PUBKEY) --pubkey-eddsa $(PUBKEY_EDDSA) & PID_LIST="$$PID_LIST $$!"; \
	go run main.go --key third --parties first,second,third,fourth --session $(SESSION) reshare --chaincode $(CHAINCODE) --old-parties first,second,third --pubkey $(PUBKEY) --pubkey-eddsa $(PUBKEY_EDDSA) & PID_LIST="$$PID_LIST $$!"; \
	go run main.go --key fourth --parties first,second,third,fourth --session $(SESSION) reshare --chaincode $(CHAINCODE) --old-parties first,second,third & PID_LIST="$$PID_LIST $$!"; \
	wait $$PID_LIST

clean:
	kill $$PID_LIST
