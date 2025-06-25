package tss

import (
	"fmt"
	"testing"
)

func TestGetLocalUIEddsa(t *testing.T) {
	input := `{
  "pub_key": "a33913681096e7c4fe821842deff2318237dc20a7b92f4e5b9950f280e55af66",
  "ecdsa_local_data": {
    "PaillierSK": null,
    "NTildei": null,
    "H1i": null,
    "H2i": null,
    "Alpha": null,
    "Beta": null,
    "P": null,
    "Q": null,
    "Xi": null,
    "ShareID": null,
    "Ks": null,
    "NTildej": null,
    "H1j": null,
    "H2j": null,
    "BigXj": null,
    "PaillierPKs": null,
    "ECDSAPub": null
  },
  "eddsa_local_data": {
    "Xi": 5231158039894169363379366388426835707932507567379061162819474058794558234398,
    "ShareID": 497331745582092701283138,
    "Ks": [
      497331745582092700104499,
      497331745582092701283138,
      119612734217614067152069389148514929657917185495136509328700997
    ],
    "BigXj": [
      {
        "Curve": "ed25519",
        "Coords": [
          45535243938868467437871260605131404549386899949516598257900260430374301183089,
          21678270081400427831174603005261595997758236129269497388302233710910404066502
        ]
      },
      {
        "Curve": "ed25519",
        "Coords": [
          55260741308402704750421491177036966169368672840564831474856711287832600198388,
          551554769987317777865954480092674697035454713618400033000942177741238713075
        ]
      },
      {
        "Curve": "ed25519",
        "Coords": [
          4753004694611641318683126026724293936065653852937799593231554256808742342146,
          23012670733022371046339798789055650368801427975612857237698317301868542957128
        ]
      }
    ],
    "EDDSAPub": {
      "Curve": "ed25519",
      "Coords": [
        5963227606565308215169422674163375708496872415988716444525718486428576003094,
        46445695821927022319290177131919550101647510516075830675056924414112557119907
      ]
    }
  },
  "keygen_committee_keys": [
    "Johnny’s MacBook Pro-A6E",
    "iPhone-473",
    "iPhone-F3B"
  ],
  "local_party_key": "iPhone-F3B",
  "chain_code_hex": "",
  "reshare_prefix": ""
}`
	result, err := GetLocalUIEddsa(input)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(result)
}
