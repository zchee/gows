package artifact

import (
	"github.com/go-json-experiment/json"
)

func decodeStrictJSON(raw []byte, target any) error {
	return json.Unmarshal(raw, target, json.RejectUnknownMembers(true))
}
