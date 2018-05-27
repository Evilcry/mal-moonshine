package utils

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// FetchJSON function
// generic JSON unmarshaller
func FetchJSON(url string, target interface{}) error {
	client := &http.Client{Timeout: 10 * time.Second}
	var getData []byte

	req, err := http.NewRequest(http.MethodGet, url, bytes.NewReader(getData))
	if err != nil {
		log.Fatal(err)
		return err
	}

	req.Header.Add("User-Agent", "Mal-Moonshine")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return err
	}

	return json.NewDecoder(res.Body).Decode(target)
}
