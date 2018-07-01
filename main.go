package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/evilcry/mal-moonshine/hybridanalysis"
	"github.com/evilcry/mal-moonshine/utils"
)

func args() *utils.Options {
	opts := utils.Options{}
	opts.FileExtensions = flag.String("exts", "", "list of comma separated file extensions: .exe,.dll")
	opts.VxName = flag.String("vx", "", "VxFamily")
	opts.Processes = flag.String("procs", "", "list of comma separated spawned processes, matches if at least one item is found")
	opts.FileType = flag.String("type", "", "FileType is more reliable than extension for file identification es: composite,rich,PE32")
	// TBI
	opts.Cmdline = flag.String("cmd", "", "specify CommandLine content, es: certutil -urlcache -split")
	// TBI
	opts.Output = flag.String("out", "", "dump JSON to file")
	flag.Parse()

	return &opts
}

func main() {
	log.Println("Mal-Moonshine fetching started...")
	opts := args()

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

	fltData := hybridanalysis.FilterFunnel(TopLevelEntry.Data, opts)
	hybridanalysis.ShowFiltered(fltData)

	log.Println("Fetching Completed")
}
