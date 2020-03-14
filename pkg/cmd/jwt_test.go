package jwt

import (
	"testing"
	"time"
)

func TestDecodeBadToken(t *testing.T) {
	qqq := struct {
		Exp int64 `json:"exp"`
	}{
		Exp: time.Now().Add(time.Hour).Unix(),
	}
	err := Decode("a.a.a.a", &qqq)
	if err == nil {
		t.Errorf("Decode() error %v", err)
	}
	err = Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODQwNDI0NzB9.In1vJz3MOArHS41Z9Wzd7BWMTrTjQsFZkYB7OtV6lPw", &qqq)
	if err != nil {
		t.Errorf("Decode() error %v", err)
	}
}

func TestEncode(t *testing.T) {
	encode, err := Encode("shuhrat", []byte("Admin"))
	if err != nil {
		t.Errorf("Encode() error %v", err)
	}
	if encode != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.InNodWhyYXQi.mRUZztnHpmmPgoQVwqmskqLKlDwgKUGIKM5E0Fla3oY" {
		t.Errorf("Encode() error: %s", encode)
	}
}

func TestVerify(t *testing.T) {
	verify, err := Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.InNodWhyYXQi.mRUZztnHpmmPgoQVwqmskqLKlDwgKUGIKM5E0Fla3oY", []byte("Admin"))
	if err != nil {
		t.Errorf("... %v", err)
	}
	if !verify {
		t.Errorf("Error")
	}
	verify, err = Verify("....", []byte("Admin"))
	if err == nil{
		t.Errorf("Bad token")
	}

	verify, err = Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.InNodWhyYXQi.mRUZztnHpmmPgoQVwqmskqLKlDwgKUGIKM5E0F55la3oY", []byte("Adamin"))
	if verify {
		t.Errorf("Not correct token")
	}
}

func TestIsNotExpired(t *testing.T) {
	expired, err := IsNotExpired("aaa", time.Now())
	if err == nil {
		t.Errorf("Bad structure, %v", err)
	}
	if expired {
		t.Errorf("...")
	}
}

func Test_splitToken(t *testing.T) {
	token, err := splitToken("a.a.a")
	if err != nil {
		t.Errorf("Bad token: %v", err)
	}
	if token[0] == "a" {
		if token[1] == "a" {
			if token[2] != "a" {
				t.Errorf("wrong conclusion")
			}
		} else {
			t.Errorf("wrong conclusion")
		}
	}else {
		t.Errorf("wrong conclusion")
	}
	_, err = splitToken("a.a.a.a")
	if err == nil {
		t.Errorf("Bad token: %v", err)
	}
}