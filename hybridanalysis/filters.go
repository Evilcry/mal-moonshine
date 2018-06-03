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

// FilterFunnel function
// gathers all specified options and applies filters
func FilterFunnel(data []Datum, opts *utils.Options) *FltDatum {
	flt := FltSubmitname(data, *opts.FileExtensions)
	flt = FltVxname(flt.Data, *opts.VxName)
	return &flt
}

// FltVxname function
// VxFamily filter
func FltVxname(data []Datum, vx string) FltDatum {
	flt := FltDatum{}
	if vx != "" {
		for _, elem := range data {
			if (elem.Vxfamily != nil) && (*elem.Vxfamily == vx) {
				flt.Data = append(flt.Data, elem)
			}
		}
	} else {
		flt.Data = data
	}
	return flt
}

// FltSubmitname function
// filter by file extension, accepted: nil (all entries) or more comma separated exts
func FltSubmitname(data []Datum, exts string) FltDatum {
	ext := strings.Split(exts, ",")
	fltDatum := FltDatum{}
	for _, elem := range data {
		if elem.Submitname != nil {
			if utils.ContainsAnyof(*elem.Submitname, ext) {
				fltDatum.Data = append(fltDatum.Data, elem)
			}
		}
	}
	return fltDatum
}

// ShowFiltered function
// shows filtered results
func ShowFiltered(flt *FltDatum) {
	for _, elem := range flt.Data {
		fmt.Println("Submitname:", *elem.Submitname)
		fmt.Println("SHA256:", elem.Sha256)
	}
}
