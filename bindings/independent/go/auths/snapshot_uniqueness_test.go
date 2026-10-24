package auths

import (
    "encoding/hex"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
)

func TestSharedSnapshotUniquenessCorpus(t *testing.T) {
    input, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "core", "fixtures", "codec", "snapshot-uniqueness-v1.json"))
    if err != nil { t.Fatal(err) }
    var corpus struct {
        Schema string `json:"schema"`
        Cases []struct {
            Name string `json:"name"`
            Kind string `json:"kind"`
            Accepts bool `json:"accepts"`
            CBOR string `json:"snapshot_cbor_hex"`
        } `json:"cases"`
    }
    if err := json.Unmarshal(input, &corpus); err != nil { t.Fatal(err) }
    if corpus.Schema != "auths-proof-status-snapshot-uniqueness/v1" || len(corpus.Cases) == 0 {
        t.Fatal("missing or wrong shared snapshot corpus")
    }
    for _, vector := range corpus.Cases {
        t.Run(vector.Name, func(t *testing.T) {
            input, err := hex.DecodeString(vector.CBOR)
            if err != nil { t.Fatal(err) }
            value, err := decodeValue(input)
            if err != nil { t.Fatal(err) }
            switch vector.Kind {
            case "principal":
                _, err = decodePrincipalSnapshot(value)
            case "grant":
                _, err = decodeGrantSnapshot(value)
            default:
                t.Fatal("unknown snapshot kind")
            }
            if (err == nil) != vector.Accepts {
                t.Fatalf("accepts=%v, expected=%v, err=%v", err == nil, vector.Accepts, err)
            }
        })
    }
}
