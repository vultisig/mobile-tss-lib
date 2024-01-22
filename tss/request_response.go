package tss

type KeygenRequest struct {
	LocalPartyID string
	AllParties   []string
}
type KeygenECDSARequest struct {
	KeygenRequest
}
type KeygenECDSAResponse struct {
	PubKey string `json:"pub_key"`
}
type KeygenEDDSARequest struct {
	KeygenRequest
}
type KeygenEDDSAResponse struct {
	PubKey string `json:"pub_key"`
}
type KeysignECDSARequest struct{}
type KeysignECDSAResponse struct{}
type KeysignEDDSARequest struct{}
type KeysignEDDSAResponse struct{}
