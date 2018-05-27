package main

import (
	"fmt"
	"log"
	"os"

	"github.com/evilcry/mal-moonshine/hybridanalysis"
	"github.com/evilcry/mal-moonshine/utils"
)

func main() {
	log.Println("Mal-Moonshine fetching started...")

	TopLevelEntry := hybridanalysis.TopLevel{}

	err := utils.FetchJSON(hybridanalysis.Url, &TopLevelEntry)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	if TopLevelEntry.Status != "ok" {
		log.Fatal("HA: status KO")
		os.Exit(1)
	}

	fmt.Println("Item Count:", TopLevelEntry.Count)
	log.Println("Fetching Completed")
}
