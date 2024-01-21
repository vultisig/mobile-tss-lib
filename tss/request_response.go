package tss

type KeygenRequest struct {
	LocalPartyID string
	AllParties   []string
}
type KeygenECDSARequest struct {
	KeygenRequest
}
type KeygenECDSAResponse struct{}
type KeygenEDDSARequest struct {
	KeygenRequest
}
type KeygenEDDSAResponse struct{}
type KeysignECDSARequest struct{}
type KeysignECDSAResponse struct{}
type KeysignEDDSARequest struct{}
type KeysignEDDSAResponse struct{}
