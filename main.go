package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/evilcry/mal-moonshine/hybridanalysis"
)

// it's just temporary
var url = "https://www.hybrid-analysis.com/feed?json"

func fetchJSON(url string, target interface{}) error {
	client := &http.Client{Timeout: 5 * time.Second}
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

func main() {
	fmt.Println("JSON fetching experiments")
	log.Println("Fetching Started...")

	TopLevelEntry := hybridanalysis.TopLevel{}

	err := fetchJSON(url, &TopLevelEntry)
	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("Item Count:", TopLevelEntry.Count)
	log.Println("Fetching Completed")

}
