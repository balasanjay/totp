package totp

import (
	"code.google.com/p/rsc/qr"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"time"
)

// BarcodeImage creates a QR code for use with Google Authenticator (GA).
// label is the string that GA uses in the UI. secretkey should be this user's
// secret key. opt should be the configured Options for this TOTP. If a nil
// options is passed, then DefaultOptions is used.
func BarcodeImage(label string, secretkey []byte, opt *Options) ([]byte, error) {
	if opt == nil {
		opt = DefaultOptions
	}

	u := &url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   fmt.Sprintf("/%s", label),
	}

	params := url.Values{
		"secret": {base32.StdEncoding.EncodeToString(secretkey)},
		"digits": {strconv.Itoa(int(opt.Digits))},
		"period": {strconv.Itoa(int(opt.TimeStep / time.Second))},
	}

	u.RawQuery = params.Encode()

	c, err := qr.Encode(u.String(), qr.M)

	if err != nil {
		return nil, err
	}

	return c.PNG(), nil
}

// Options contains the different configurable values for a given TOTP
// invocation.
type Options struct {
	Time     func() time.Time
	Tries    []int64
	TimeStep time.Duration
	Digits   uint8
	Hash     func() hash.Hash
}

// NewOptions constructs a pre-configured Options. The returned Options' uses
// time.Now to get the current time, has a window size of 30 seconds, and
// tries the currently active window, and the previous one. It expects 6 digits,
// and uses sha1 for its hash algorithm. These settings were chosen to be
// compatible with Google Authenticator.
func NewOptions() *Options {
	return &Options{
		Time:     time.Now,
		Tries:    []int64{0, -1},
		TimeStep: 30 * time.Second,
		Digits:   6,
		Hash:     sha1.New,
	}
}

var DefaultOptions = NewOptions()

var digit_power = []int64{
	1,          // 0
	10,         // 1
	100,        // 2
	1000,       // 3
	10000,      // 4
	100000,     // 5
	1000000,    // 6
	10000000,   // 7
	100000000,  // 8
	1000000000, // 9
}

// Authenticate verifies the TOTP userCode taking the key from secretKey and
// other options from o, the provided Options. If o is nil, then
// DefaultOptions is used instead.
func Authenticate(secretKey []byte, userCode string, o *Options) bool {
	if o == nil {
		o = DefaultOptions
	}

	if int(o.Digits) != len(userCode) {
		return false
	}

	uc, err := strconv.ParseInt(userCode, 10, 64)
	if err != nil {
		return false
	}

	t := o.Time().Unix() / int64(o.TimeStep/time.Second)
	var tbuf [8]byte

	hm := hmac.New(o.Hash, secretKey)
	var hashbuf []byte

	for i := 0; i < len(o.Tries); i++ {
		b := t + o.Tries[i]

		tbuf[0] = byte(b >> 56)
		tbuf[1] = byte(b >> 48)
		tbuf[2] = byte(b >> 40)
		tbuf[3] = byte(b >> 32)
		tbuf[4] = byte(b >> 24)
		tbuf[5] = byte(b >> 16)
		tbuf[6] = byte(b >> 8)
		tbuf[7] = byte(b)

		hm.Reset()
		hm.Write(tbuf[:])
		hashbuf = hm.Sum(hashbuf[:0])

		offset := hashbuf[len(hashbuf)-1] & 0xf
		truncatedHash := hashbuf[offset:]

		code := int64(truncatedHash[0])<<24 |
			int64(truncatedHash[1])<<16 |
			int64(truncatedHash[2])<<8 |
			int64(truncatedHash[3])

		code &= 0x7FFFFFFF
		code %= digit_power[len(userCode)]

		if code == uc {
			return true
		}
	}

	return false
}
