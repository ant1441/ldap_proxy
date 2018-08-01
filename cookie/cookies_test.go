package cookie

import (
	"encoding/base64"
	"testing"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuv"
	const token = "my access token"
	c, err := NewCipher([]byte(secret))
	if err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	encoded, err := c.Encrypt(token)
	if err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	decoded, err := c.Decrypt(encoded)
	if err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	if token == encoded {
		t.Errorf("token should not be equal to encodeded value: %+v %+v", token, encoded)
	}

	if token != decoded {
		t.Errorf("token %+v does not match decode value %+v", token, decoded)
	}

}

func TestEncodeAndDecodeAccessTokenB64(t *testing.T) {
	const secret64 = "A3Xbr6fu6Al0HkgrP1ztjb-mYiwmxgNPP-XbNsz1WBk="
	const token = "my access token"

	secret, err := base64.URLEncoding.DecodeString(secret64)
	c, err := NewCipher([]byte(secret))
	if err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	encoded, err := c.Encrypt(token)
	if err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	decoded, err := c.Decrypt(encoded)
	if err != nil {
		t.Errorf("unexpected error: %+v", err)
	}

	if token == encoded {
		t.Errorf("token should not be equal to encodeded value: %+v %+v", token, encoded)
	}

	if token != decoded {
		t.Errorf("token %+v does not match decode value %+v", token, decoded)
	}
}
