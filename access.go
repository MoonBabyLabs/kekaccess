package kekaccess

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/revel/modules/csrf/app"
	"io/ioutil"
	"github.com/mitchellh/go-homedir"
	"time"
	"encoding/json"
	"errors"
)

type Access struct {
}

const TOKEN_LENGTH = 25

const SIGNING_METHOD = "HS256"

const SECRET_PATH = "/.kek/s"

const TOKENS_PATH = "/.kek/tokens"

type KekClaim struct {
	jwt.StandardClaims
	AccessToken string
	Data interface{}
}

type KekAccess struct {
	Valid bool `json:"valid"`
	Write bool `json:"write"`
	Read bool `json:"read"`
	Publish bool `json:"publish"`
	Delete bool `json:"delete"`
	Update bool `json:"update"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Tokens map[string]KekAccess

func (jt Access) NewJwt(accessToken string, data map[string]string) (string, error) {
	// Create the Claims
	savedSecretBytes, _ := jt.GetSecret()
	kc := KekClaim{}
	kc.ExpiresAt = time.Now().Add(time.Minute * 40).Unix()
	kc.AccessToken = accessToken
	token := jwt.NewWithClaims(jwt.GetSigningMethod(SIGNING_METHOD), kc)
	return token.SignedString(savedSecretBytes)
}

func (jt Access) ValidateJwtAccess(tokenString string, accessType string) error {
	// Parse the token
	kc := KekClaim{}
	_, vErr := jwt.ParseWithClaims(tokenString, &kc, func(token *jwt.Token) (interface{}, error) {
		return jt.GetSecret()
	})

	if vErr != nil {
		return vErr
	}

	accessTokens := jt.GetValidTokens()

	if !inList(kc.AccessToken, accessTokens) {
		return errors.New("Either token has been marked invalid or unable to find access token in list")
	}

	access := accessTokens[kc.AccessToken]

	switch accessType {
	case "write":
		if access.Write {
			return nil
		} else {
			return errors.New("This token has invalid access to perform write actions")
		}
	case "delete":
		if access.Delete {
			return nil
		} else {
			return errors.New("This token has invalid access to perform delete actions")
		}
	case "update":
		if access.Update {
			return nil
		} else {
			return errors.New("This token has invalid access to perform update actions")
		}
	case "publish":
		if access.Publish {
			return nil
		} else {
			return errors.New("This token has invalid access to perform publish actions")
		}
	case "read":
		if access.Read {
			return nil
		} else {
			return errors.New("This token has invalid access to perform read actions")
		}
	default:
		return errors.New("accessType is invalid, must be of the following: read, write, update, publish, delete")
	}
}

func (jt Access) GenerateSecret(path string) []byte {
	rnd, _ := csrf.RandomString(128)
	home, _ := homedir.Dir()
	ioutil.WriteFile(home + SECRET_PATH, []byte(rnd), 0755)

	return []byte(rnd)
}

func (jt Access) GenerateAccessToken(read, write, update, delete, publish bool) (string, Tokens) {
	token, _ :=  csrf.RandomString(TOKEN_LENGTH)
	tokenList := jt.GetAllTokens()

	for inList(token, tokenList) {
		token, _ = csrf.RandomString(TOKEN_LENGTH)
	}

	tokenList[token] = KekAccess{
		Valid: true,
		Read: read,
		Write: write,
		Update: update,
		Publish: publish,
		Delete: delete,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return token, tokenList
}

func inList(t string, list Tokens) bool {
	_, exists := list[t]

	return exists
}

func (jt Access) AddAccessToken(canWrite, canDelete, canUpdate, canPublish, canRead bool) string {
	tkn, tokenList := jt.GenerateAccessToken(canRead, canWrite, canUpdate, canDelete, canPublish)
	updData, _ := json.Marshal(tokenList)
	home, _ := homedir.Dir()
	ioutil.WriteFile(home + TOKENS_PATH, updData, 0755)

	return tkn
}

func (jt Access) GetAllTokens() Tokens {
	home, _ := homedir.Dir()
	data, _ := ioutil.ReadFile(home + TOKENS_PATH)
	tokenData := Tokens{}
	json.Unmarshal(data, &tokenData)

	return tokenData
}

func (jt Access) GetValidTokens() Tokens {
	tokenData := jt.GetAllTokens()

	for token, access := range tokenData {
		if !access.Valid {
			delete(tokenData, token)
		}
	}

	return tokenData
}

func (jt Access) GetInvalidTokens() Tokens {
	tokenList := jt.GetAllTokens()

	for token, access := range tokenList {
		if access.Valid {
			delete(tokenList, token)
		}
	}

	return tokenList
}

func (jt Access) GetSecret() ([]byte, error) {
	home, _ := homedir.Dir()
	return ioutil.ReadFile(home + SECRET_PATH)
}

