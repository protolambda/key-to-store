package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/uuid"
	hbls "github.com/herumi/bls-eth-go-binary/bls"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	"os"
)

func init() {
	hbls.Init(hbls.BLS12_381)
	hbls.SetETHmode(hbls.EthModeLatest)
}

func MarshalJSON(key *hbls.SecretKey, pass []byte) ([]byte, error) {
	data := make(map[string]interface{})
	// TODO: ligthouse can't handle this field, should it be here?
	//data["name"] = ke.name
	encryptor := keystorev4.New(keystorev4.WithCipher("pbkdf2"))
	var err error
	data["crypto"], err = encryptor.Encrypt(key.Serialize(), pass)
	if err != nil {
		return nil, err
	}
	// Empty, just for wallets etc.
	data["path"] = ""
	data["uuid"] = uuid.New()
	data["version"] = 4
	data["pubkey"] = fmt.Sprintf("%x", key.GetPublicKey().Serialize())
	return json.MarshalIndent(data, "", "  ")
}

func main() {
	privHex := flag.String("priv", "", "Private key, in hex bytes")
	pass := flag.String("pass", "", "keystore password, may be empty")
	flag.Parse()

	if privHex == nil || pass == nil || len(*privHex) != 64 {
		_, _ = fmt.Fprintf(os.Stderr, "missing/malformatted arg")
		os.Exit(1)
	}
	var secKey hbls.SecretKey
	//secKey.SetByCSPRNG()  for random key
	if err := secKey.DeserializeHexStr(*privHex); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to parse priv: %v", err)
		os.Exit(1)
	}
	dat, err := MarshalJSON(&secKey, []byte(*pass))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to marshal json keystore: %v", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(dat)
}
