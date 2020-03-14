package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

type Secret []byte

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

var defaultHeader = Header{
	Alg: alg,
	Typ: typ,
}

func Encode(payload interface{}, secret Secret) (token string, err error) {
	headerJSON, err := json.Marshal(defaultHeader)
	if err != nil {
		return "", errors.New("can't marshal header")
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", errors.New("can't marshall payload")
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signatureEncoded := calculateSignatureEncoded(headerEncoded, payloadEncoded, secret)

	return fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded), nil
}

func Decode(token string, payload interface{}) (err error) {
	parts, err := splitToken(token)
	if err != nil {
		return err
	}

	payloadEncoded := parts[1]
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return errors.New("can't decode payload")
	}
	err = json.Unmarshal(payloadJSON, payload)
	if err != nil {
		return errors.New("can't unmarshall payload")
	}

	return nil
}

func Verify(token string, secret Secret) (ok bool, err error) {
	parts, err := splitToken(token)
	if err != nil {
		return false, err
	}
	headerEncoded, payloadEncoded, signatureEncoded := parts[0], parts[1], parts[2]

	verificationEncoded := calculateSignatureEncoded(headerEncoded, payloadEncoded, secret)
	return signatureEncoded == verificationEncoded, nil
}

func IsNotExpired(payload interface{}, moment time.Time) (ok bool, err error) {
	reflectType := reflect.TypeOf(payload)
	reflectValue := reflect.ValueOf(payload)
	if reflectType.Kind() == reflect.Ptr {
		reflectType = reflectType.Elem()
		reflectValue = reflectValue.Elem()
	}

	if reflectType.Kind() != reflect.Struct {
		return false, errors.New("give me struct or pointer to it")
	}

	fieldCount := reflectType.NumField()
	for i := 0; i < fieldCount; i++ {
		field := reflectType.Field(i)
		tag, ok := field.Tag.Lookup(key)
		if !ok {
			continue
		}
		if tag == exp {
			value := reflectValue.Field(i)
			if value.Kind() != reflect.Int64 {
				return false, errors.New("exp should be int64")
			}
			exp := value.Interface().(int64)
			return exp > moment.Unix(), nil
		}
	}

	panic(errors.New("no field with json:exp tag"))
}

func splitToken(token string) (parts []string, err error) {
	parts = strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("bad token")
	}
	return parts, nil
}

func calculateSignatureEncoded(headerEncoded string, payloadEncoded string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(headerEncoded + "." + payloadEncoded))
	signature := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(signature)
}