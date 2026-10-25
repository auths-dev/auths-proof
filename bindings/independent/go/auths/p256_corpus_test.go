package auths

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestPublishedP256CorpusAndStrictAuthsDerivations(t *testing.T) {
	corpus, err := os.ReadFile("../../../../core/fixtures/crypto/p256-sha256-v1.tsv")
	if err != nil {
		t.Fatal(err)
	}
	cases, accepted := 0, 0
	keys := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSuffix(string(corpus), "\n"), "\n") {
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "id\t") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			t.Fatal("fixture fields")
		}
		name, result := fields[0], fields[4]
		switch result {
		case "ok", "invalid-key", "invalid-signature-encoding", "verification-failed":
		default:
			t.Fatalf("unknown fixture result: %s", result)
		}
		decode := func(value string) []byte {
			valueBytes, err := hex.DecodeString(value)
			if err != nil {
				t.Fatal(err)
			}
			return valueBytes
		}
		key, message, signature := decode(fields[1]), decode(fields[2]), decode(fields[3])
		if verifySignature("p256-sha256-v1", key, message, signature) != (result == "ok") {
			t.Errorf("signature verdict differs: %s", name)
		}
		if _, valid := p256PublicKey(key); valid != (fields[5] == "true") {
			t.Errorf("key verdict differs: %s", name)
		}
		cases++
		if result == "ok" {
			accepted++
			keys[fields[1]] = true
		}
	}
	if cases != 653 || accepted != 173 || len(keys) != 98 {
		t.Fatalf("incomplete corpus: %d cases, %d accepted, %d keys", cases, accepted, len(keys))
	}
}
