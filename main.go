package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/evilcry/mal-moonshine/hybridanalysis"
	"github.com/evilcry/mal-moonshine/utils"
)

func main() {
	// Temporary, better shape to be given
	exts := flag.String("exts", "", "list of comma separated file extensions: .exe,.dll")
	flag.Parse()

	log.Println("Mal-Moonshine fetching started...")

	TopLevelEntry := hybridanalysis.TopLevel{}

	err := utils.FetchJSON(hybridanalysis.Url, &TopLevelEntry)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	if TopLevelEntry.Status != "ok" || TopLevelEntry.Count == 0 {
		log.Fatal("HA: status KO or no data to fetch")
		os.Exit(1)
	}
	fmt.Println("Item Count:", TopLevelEntry.Count)

	fltData := hybridanalysis.Submitname(TopLevelEntry.Data, *exts)
	hybridanalysis.ShowFiltered(&fltData)

	log.Println("Fetching Completed")
}
