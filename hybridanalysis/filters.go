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

// Submitname function
// filter by file extension, accepted: nil (all entries) or more comma separated exts
func Submitname(data []Datum, exts string) FltDatum {
	ext := strings.Split(exts, ",")
	fltDatum := FltDatum{}
	for _, elem := range data {
		if elem.Submitname != nil {
			if utils.ContainsAnyof(*elem.Submitname, ext) {
				fltDatum.Count++
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
