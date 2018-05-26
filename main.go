package main

import (
	"fmt"
	"log"

	"github.com/evilcry/mal-moonshine/hybridanalysis"
	"github.com/evilcry/mal-moonshine/utils"
)

func main() {
	log.Println("Mal-Moonshine fetching started...")

	TopLevelEntry := hybridanalysis.TopLevel{}

	err := utils.FetchJSON(hybridanalysis.URL, &TopLevelEntry)
	if err != nil {
		log.Fatal(err)
		return
	}

	if TopLevelEntry.Status != "ok" {
		log.Fatal("HA: status KO")
		return
	}

	fmt.Println("Item Count:", TopLevelEntry.Count)
	log.Println("Fetching Completed")
}
