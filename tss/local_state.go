package tss

import "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"

// LocalState represent the information that will be saved locally
type LocalState struct {
	PubKey              string                    `json:"pub_key"`
	LocalData           keygen.LocalPartySaveData `json:"local_data"`
	KeygenCommitteeKeys []string                  `json:"keygen_committee_keys"`
	LocalPartyKey       string                    `json:"local_party_key"`
}
