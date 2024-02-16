package tss

import (
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
)

// LocalState represent the information that will be saved locally
type LocalState struct {
	PubKey              string                         `json:"pub_key"`
	ECDSALocalData      keygen.LocalPartySaveData      `json:"ecdsa_local_data"`
	EDDSALocalData      eddsaKeygen.LocalPartySaveData `json:"eddsa_local_data"`
	KeygenCommitteeKeys []string                       `json:"keygen_committee_keys"`
	LocalPartyKey       string                         `json:"local_party_key"`
	ChainCodeHex        string                         `json:"chain_code_hex"`
}
