package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"os"
	"testing"
	"time"
)

func TestPrint(t *testing.T) {
	b, err := BarcodeImage("foo@bar.com", []byte("hello"), nil)
	if err != nil {
		t.Errorf("expecting no error, got %q", err)
	}

	if len(b) <= 0 {
		t.Errorf("expecting b to be non-empty")
	}

	return

	// This code is for manual testing of the library functionality

	// Authenticates to test authentication
	t.Logf("Authenticate=%v", Authenticate([]byte("hello"), "493478", nil))

	// Creates a QR code
	f, err := os.Create("foo.png")
	if err != nil {
		t.Errorf("Could not create file: %v", err)
		return
	}

	_, err = f.Write(b)
	if err != nil {
		t.Errorf("Could not write barcode: %v", err)
		return
	}
}

func TestVarious(t *testing.T) {
	s20 := "3132333435363738393031323334353637383930"
	s32 := "3132333435363738393031323334353637383930" +
		"313233343536373839303132"
	s64 := "3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"31323334"

	var secrets [][]byte

	for _, v := range []string{s20, s32, s64} {
		sec, _ := hex.DecodeString(v)
		secrets = append(secrets, []byte(sec))
	}

	tests := []struct {
		time  int64
		totps []string
	}{
		{time: 59, totps: []string{"94287082", "46119246", "90693936"}},
		{time: 1111111109, totps: []string{"07081804", "68084774", "25091201"}},
		{time: 1111111111, totps: []string{"14050471", "67062674", "99943326"}},
		{time: 1234567890, totps: []string{"89005924", "91819424", "93441116"}},
		{time: 2000000000, totps: []string{"69279037", "90698825", "38618901"}},
		{time: 20000000000, totps: []string{"65353130", "77737706", "47863826"}},
	}

	for _, c := range tests {
		for i, h := range []func() hash.Hash{sha1.New, sha256.New, sha512.New} {
			if i >= len(c.totps) {
				break
			}

			opt := NewOptions()
			opt.Time = func() time.Time {
				return time.Unix(c.time, 0)
			}
			opt.Tries = []int64{0}
			opt.TimeStep = 30 * time.Second
			opt.Digits = 8
			opt.Hash = h

			// Test the simple case
			auth := Authenticate(secrets[i], c.totps[i], opt)
			if !auth {
				t.Errorf("should have authenticated, but didn't. TOTP:%q Unix-Time:%v", c.totps[i], c.time)
				continue
			}

			// Test that the tries array works as intended
			newtime := c.time - int64(opt.TimeStep/time.Second)
			opt.Tries = []int64{0, 1}
			opt.Time = func() time.Time {
				return time.Unix(newtime, 0)
			}
			auth = Authenticate(secrets[i], c.totps[i], opt)
			if !auth {
				t.Errorf("should have authenticated, but didn't. TOTP:%q Unix-Time:%v", c.totps[i], newtime)
				continue
			}

			// Modify the TOTP, and make sure that it fails
			failtotp := []byte(c.totps[i])
			failtotp[0] = ((failtotp[0]-'0')+1)%('9'-'0') + '0'
			auth = Authenticate(secrets[i], string(failtotp), opt)
			if auth {
				t.Errorf("should have failed to authenticate, but didnt. TOTP:%q Unix-Time:%v", failtotp, c.time)
				continue
			}
		}
	}
}
