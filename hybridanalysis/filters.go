package hybridanalysis

import (
	"fmt"
	"strings"

	"github.com/evilcry/mal-moonshine/utils"
)

// FltDatum filtered
// Count: items found, Data array
type FltDatum struct {
	Count int
	Data  []Datum
}

// FilterFunnel func
// all filtering logic
func FilterFunnel(data []Datum, opts *utils.Options) *FltDatum {
	flt := FltDatum{}
	for _, elem := range data {
		if !FltSubmitname(elem.Submitname, opts.FileExtensions) {
			continue
		}
		if !FltVxfamily(elem.Vxfamily, *opts.VxName) {
			continue
		}
		if !FltProcesses(elem.ProcessList, opts) {
			continue
		}

		flt.Count++
		flt.Data = append(flt.Data, elem)
	}
	return &flt
}

// FltProcesses function
// filter ProcessNames and/or CommandLine
func FltProcesses(processList []ProcessList, opts *utils.Options) bool {
	// TBI
	// procList := strings.Split(*opts.Processes, ",")
	// cmdLine := *opts.Cmdline
	return true
}

// FltSubmitname func
// submitname filter
func FltSubmitname(submitName, fileExts *string) bool {
	exts := strings.Split(*fileExts, ",")
	if submitName != nil {
		if utils.ContainsAnyof(*submitName, exts) {
			return true
		}
	}
	return false
}

// FltVxfamily func
// vxfamily filter
func FltVxfamily(vxFamily *string, vxString string) bool {
	if vxString == "" {
		return true
	} else if vxFamily != nil {
		if *vxFamily != vxString {
			return false
		}
	}
	return true
}

// ShowFiltered function
// shows filtered results
func ShowFiltered(flt *FltDatum) {
	fmt.Println("Filtered:", flt.Count)
	for _, elem := range flt.Data {
		fmt.Println("Submitname:", *elem.Submitname)
		fmt.Println("SHA256:", elem.Sha256)
	}
}
