package tss

type KeygenRequest struct {
	LocalPartyID string
	AllParties   []string
}
type KeygenResponse struct {
	PubKey string `json:"pub_key"`
}
type KeysignRequest struct {
	PubKey               string   `json:"pub_key"`
	MessageToSign        string   `json:"message_to_sign"` // base64 encoded message that need to be signed
	KeysignCommitteeKeys []string `json:"keysign_committee_keys"`
	LocalPartyKey        string   `json:"local_party_key"`
}
type Signature struct {
	Msg        string `json:"msg"`
	R          string `json:"r"`
	S          string `json:"s"`
	RecoveryID string `json:"recovery_id"` // mostly used in ETH
}
type KeysignResponse struct {
	Signature Signature `json:"signature"`
}
