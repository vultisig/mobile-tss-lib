.PHONY: all keygen keysign reshare clean

# Common variables
CHAINCODE = 80871c0f885f953e5206e461630a9222148797e66276a83224c7b9b0f75b3ec0
PUBKEY = 026ee60a4c36514460e586a8cf278fc4c44875edacd1084a9c22d7db2c96fbd555
PUBKEY_EDDSA = eb92398e665fe67714257ca3c6b68e4b7ff16b5c9c3523e9301c6d6d82d353fb
MESSAGE = aGVsbG8gd29ybGQK
DERIVEPATH = "m/84'/0'/0'/0/0"
SESSION := $(shell echo $$RANDOM)

all: keygen keysign reshare

keygen:
	trap 'kill $$PID_LIST' SIGINT; \
	go run main.go --key first --parties first,second,third --session $(SESSION) --leader keygen --chaincode $(CHAINCODE)  & PID_LIST=$$!; \
	go run main.go --key second --parties first,second,third --session $(SESSION) keygen --chaincode $(CHAINCODE) & PID_LIST="$$PID_LIST $$!"; \
	go run main.go --key third --parties first,second,third --session $(SESSION) keygen --chaincode $(CHAINCODE) & PID_LIST="$$PID_LIST $$!"; \
	wait $$PID_LIST

keysign:
	trap 'kill $$PID_LIST' SIGINT; \
	go run main.go --key first --parties first,second --session $(SESSION) --leader signECDSA --pubkey $(PUBKEY) --message $(MESSAGE) --derivepath $(DERIVEPATH) & PID_LIST=$$!; \
	go run main.go --key second --parties first,second --session $(SESSION) signECDSA --pubkey $(PUBKEY) --message $(MESSAGE) --derivepath $(DERIVEPATH) & PID_LIST="$$PID_LIST $$!"; \
	wait $$PID_LIST

reshare:
	trap 'kill $$PID_LIST' SIGINT; \
	go run main.go --key first --parties first,second,third,fourth --session $(SESSION) --leader reshare --chaincode $(CHAINCODE) --old-parties first,second,third --pubkey $(PUBKEY) --pubkey-eddsa $(PUBKEY_EDDSA) & PID_LIST=$$!; \
	go run main.go --key second --parties first,second,third,fourth --session $(SESSION) reshare --chaincode $(CHAINCODE) --old-parties first,second,third --pubkey $(PUBKEY) --pubkey-eddsa $(PUBKEY_EDDSA) & PID_LIST="$$PID_LIST $$!"; \
	go run main.go --key third --parties first,second,third,fourth --session $(SESSION) reshare --chaincode $(CHAINCODE) --old-parties first,second,third --pubkey $(PUBKEY) --pubkey-eddsa $(PUBKEY_EDDSA) & PID_LIST="$$PID_LIST $$!"; \
	go run main.go --key fourth --parties first,second,third,fourth --session $(SESSION) reshare --chaincode $(CHAINCODE) --old-parties first,second,third & PID_LIST="$$PID_LIST $$!"; \
	wait $$PID_LIST

clean:
	kill $$PID_LIST
