package main

import "time"

type Base struct {
	Encrypted bool `json:"encrypted"`
	Folders   []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"folders"`
	Items []struct {
		PasswordHistory []struct {
			LastUsedDate time.Time `json:"lastUsedDate"`
			Password     string    `json:"password"`
		} `json:"passwordHistory"`
		RevisionDate   time.Time  `json:"revisionDate"`
		CreationDate   time.Time  `json:"creationDate"`
		DeletedDate    *time.Time `json:"deletedDate"`
		ID             string     `json:"id"`
		OrganizationID *string    `json:"organizationId"`
		FolderID       *string    `json:"folderId"`
		Type           int        `json:"type"`
		Reprompt       int        `json:"reprompt"`
		Name           string     `json:"name"`
		Notes          string     `json:"notes"`
		Favorite       bool       `json:"favorite"`
		Login          struct {
			Fido2Credentials *string `json:"fido2Credentials"`
			Uris             *[]struct {
				Match *string `json:"match"`
				URI   string  `json:"uri"`
			} `json:"uris"`
			Username string  `json:"username"`
			Password string  `json:"password"`
			Totp     *string `json:"totp"`
		} `json:"login,omitempty"`
		CollectionIds *int `json:"collectionIds"`
		Fields        *[]struct {
			Name     string  `json:"name"`
			Value    string  `json:"value"`
			Type     int     `json:"type"`
			LinkedID *string `json:"linkedId"`
		} `json:"fields,omitempty"`
		SecureNote struct {
			Type int `json:"type"`
		} `json:"secureNote,omitempty"`
	} `json:"items"`
}
