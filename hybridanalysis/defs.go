package hybridanalysis

import (
	"bytes"
	"encoding/json"
	"errors"
)

// URL const
// hybrid-analysis
const (
	Url = "https://www.hybrid-analysis.com/feed?json"
)

// UnmarshalTopLevel ctor
// HA unmarshaller
func UnmarshalTopLevel(data []byte) (TopLevel, error) {
	var r TopLevel
	err := json.Unmarshal(data, &r)
	return r, err
}

// Marshal ctor
// HA marshaller
func (r *TopLevel) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// TopLevel struct
// contains all analysis
type TopLevel struct {
	Count  int64   `json:"count"`
	Status string  `json:"status"`
	Data   []Datum `json:"data"`
}

// Datum struct
// contains analysis data
type Datum struct {
	Md5                    string                 `json:"md5"`
	Sha1                   string                 `json:"sha1"`
	Sha256                 string                 `json:"sha256"`
	Isinteresting          bool                   `json:"isinteresting"`
	AnalysisStartTime      string                 `json:"analysis_start_time"`
	Threatscore            int64                  `json:"threatscore"`
	Threatlevel            int64                  `json:"threatlevel"`
	ThreatlevelHuman       ThreatlevelHuman       `json:"threatlevel_human"`
	Avdetect               *int64                 `json:"avdetect"`
	Isunknown              bool                   `json:"isunknown"`
	Vxfamily               *string                `json:"vxfamily"`
	Submitname             *string                `json:"submitname"`
	Isurlanalysis          *bool                  `json:"isurlanalysis"`
	Size                   *int64                 `json:"size"`
	Type                   *string                `json:"type"`
	EtAlertsTotal          *int64                 `json:"et_alerts_total"`
	EtAlertsRealTotal      *int64                 `json:"et_alerts_real_total"`
	Domains                []string               `json:"domains"`
	Hosts                  []string               `json:"hosts"`
	HostsGeo               []HostsGeo             `json:"hosts_geo"`
	CompromisedHosts       []string               `json:"compromised_hosts"`
	EtAlerts               []EtAlert              `json:"et_alerts"`
	EnvironmentID          EnvironmentID          `json:"environmentId"`
	EnvironmentDescription EnvironmentDescription `json:"environmentDescription"`
	Sharedanalysis         bool                   `json:"sharedanalysis"`
	Isreliable             bool                   `json:"isreliable"`
	Reporturl              string                 `json:"reporturl"`
	VTDetect               *int64                 `json:"vt_detect"`
	MSDetect               *int64                 `json:"ms_detect"`
	ProcessList            []ProcessList          `json:"process_list"`
	ExtractedFiles         []ExtractedFile        `json:"extracted_files"`
	HostsCapped            *bool                  `json:"hosts_capped"`
	Tags                   []string               `json:"tags"`
	PublicReferences       []string               `json:"public_references"`
}

// EtAlert struct
// contains traffic ET detections
type EtAlert struct {
	Destip   *string  `json:"destip"`
	Destport string   `json:"destport"`
	Protocol Protocol `json:"protocol"`
	Action   Action   `json:"action"`
	Srcip    *string  `json:"srcip"`
}

// Action struct
// contains AV profiling
type Action struct {
	Signatureid  string   `json:"signatureid"`
	Signaturerev string   `json:"signaturerev"`
	Severity     Severity `json:"severity"`
	Category     Category `json:"category"`
	Description  string   `json:"description"`
}

// ExtractedFile struct
// contains carved file details
type ExtractedFile struct {
	Name                string              `json:"name"`
	FilePath            string              `json:"file_path"`
	FileSize            string              `json:"file_size"`
	Sha256              *string             `json:"sha256"`
	TypeTags            []TypeTag           `json:"type_tags"`
	Threatlevel         int64               `json:"threatlevel"`
	ThreatlevelReadable ThreatlevelReadable `json:"threatlevel_readable"`
	AVLabel             *string             `json:"av_label"`
	AVMatched           *string             `json:"av_matched"`
	AVTotal             *string             `json:"av_total"`
}

// HostsGeo struct
// contains GeoIP information
type HostsGeo struct {
	IP  string `json:"ip"`
	Lat string `json:"lat"`
	Lon string `json:"lon"`
	Cc  string `json:"cc"`
}

// ProcessList struct
// contains processes involved
type ProcessList struct {
	Uid            string       `json:"uid"`
	Name           string       `json:"name"`
	Normalizedpath *string      `json:"normalizedpath"`
	Commandline    *Commandline `json:"commandline"`
	Sha256         *string      `json:"sha256"`
	AVLabel        *string      `json:"av_label"`
	AVMatched      *int64       `json:"av_matched"`
	AVTotal        *int64       `json:"av_total"`
	Parentuid      *string      `json:"parentuid"`
}

// EnvironmentDescription string
// analysis environment
type EnvironmentDescription string

const (
	// AndroidStaticAnalysis env
	AndroidStaticAnalysis EnvironmentDescription = "Android Static Analysis"
	// LinuxUbuntu160464Bit env
	LinuxUbuntu160464Bit EnvironmentDescription = "Linux (Ubuntu 16.04, 64 bit)"
	// Windows732Bit env
	Windows732Bit EnvironmentDescription = "Windows 7 32 bit"
	// Windows732BitHWPSupport env
	Windows732BitHWPSupport EnvironmentDescription = "Windows 7 32 bit (HWP Support)"
	// Windows764Bit env
	Windows764Bit EnvironmentDescription = "Windows 7 64 bit"
)

// EnvironmentID string
// environment identifier
type EnvironmentID string

const (
	// The100 custom env ID
	The100 EnvironmentID = "100"
	// The110 custom env ID
	The110 EnvironmentID = "110"
	// The120 custom env ID
	The120 EnvironmentID = "120"
	// The200 custom env ID
	The200 EnvironmentID = "200"
	// The300 custom env ID
	The300 EnvironmentID = "300"
)

// Category string
// malicious category
type Category string

const (
	// ANetworkTrojanWasDetected malicious category
	ANetworkTrojanWasDetected Category = "A Network Trojan was detected"
	// MiscActivity malicious category
	MiscActivity Category = "Misc activity"
	// PotentialCorporatePrivacyViolation malicious category
	PotentialCorporatePrivacyViolation Category = "Potential Corporate Privacy Violation"
	// PotentiallyBadTraffic malicious category
	PotentiallyBadTraffic Category = "Potentially Bad Traffic"
)

// Severity string
// threat severity
type Severity string

const (
	// The1 low severity
	The1 Severity = "1"
	// The2 medium severity
	The2 Severity = "2"
	// The3 high severity
	The3 Severity = "3"
)

// Protocol string
// protocols TCP/UDP
type Protocol string

const (
	// TCP protocol
	TCP Protocol = "TCP"
	// UDP protocol
	UDP Protocol = "UDP"
)

// ThreatlevelReadable string
// threat overview
type ThreatlevelReadable string

const (
	// ThreatlevelReadableMalicious malicious
	ThreatlevelReadableMalicious ThreatlevelReadable = "malicious"
	// ThreatlevelReadableNoSpecificThreat non specific threat
	ThreatlevelReadableNoSpecificThreat ThreatlevelReadable = "no specific threat"
)

// TypeTag string
// filetype
type TypeTag string

const (
	// Assembly filetype
	Assembly TypeTag = "assembly"
	// Data filetype
	Data TypeTag = "data"
	// Doc office file
	Doc TypeTag = "doc"
	// ELF linux (INTEL, ARM, MIPS, etc.)
	ELF TypeTag = "elf"
	// Empty file
	Empty TypeTag = "empty"
	// HTML html file
	HTML TypeTag = "html"
	// Img image file
	Img TypeTag = "img"
	// Java jar file
	Java TypeTag = "java"
	// Javascript js file
	Javascript TypeTag = "javascript"
	// Lnk link file
	Lnk TypeTag = "lnk"
	// Pedll PE DLL
	Pedll TypeTag = "pedll"
	// Peexe PE .exe
	Peexe TypeTag = "peexe"
	// Rtf RichTextFormat
	Rtf TypeTag = "rtf"
	// Script script file
	Script TypeTag = "script"
	// Text file
	Text TypeTag = "text"
	// The64Bits 64bit file
	The64Bits TypeTag = "64bits"
	// URL url submitted
	URL TypeTag = "url"
)

// ThreatlevelHuman string
// threatlevel
type ThreatlevelHuman string

const (
	// Suspicious suspicious
	Suspicious ThreatlevelHuman = "suspicious"
	// ThreatlevelHumanMalicious marked as malicious
	ThreatlevelHumanMalicious ThreatlevelHuman = "malicious"
	// ThreatlevelHumanNoSpecificThreat cannot define
	ThreatlevelHumanNoSpecificThreat ThreatlevelHuman = "no specific threat"
)

// Commandline struct
// contains process commandline
type Commandline struct {
	Integer *int64
	String  *string
}

// UnmarshalJSON function
// unmarshaller for Commandline
func (x *Commandline) UnmarshalJSON(data []byte) error {
	object, err := unmarshalUnion(data, &x.Integer, nil, nil, &x.String, false, nil, false, nil, false, nil, false, nil, true)
	if err != nil {
		return err
	}
	if object {
	}
	return nil
}

// MarshalJSON Commandline ctor
func (x *Commandline) MarshalJSON() ([]byte, error) {
	return marshalUnion(x.Integer, nil, nil, x.String, false, nil, false, nil, false, nil, false, nil, true)
}

func unmarshalUnion(data []byte, pi **int64, pf **float64, pb **bool, ps **string, haveArray bool, pa interface{}, haveObject bool, pc interface{}, haveMap bool, pm interface{}, haveEnum bool, pe interface{}, nullable bool) (bool, error) {
	if pi != nil {
		*pi = nil
	}
	if pf != nil {
		*pf = nil
	}
	if pb != nil {
		*pb = nil
	}
	if ps != nil {
		*ps = nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}

	switch v := tok.(type) {
	case json.Number:
		if pi != nil {
			i, err := v.Int64()
			if err == nil {
				*pi = &i
				return false, nil
			}
		}
		if pf != nil {
			f, err := v.Float64()
			if err == nil {
				*pf = &f
				return false, nil
			}
			return false, errors.New("Unparsable number")
		}
		return false, errors.New("Union does not contain number")
	case float64:
		return false, errors.New("Decoder should not return float64")
	case bool:
		if pb != nil {
			*pb = &v
			return false, nil
		}
		return false, errors.New("Union does not contain bool")
	case string:
		if haveEnum {
			return false, json.Unmarshal(data, pe)
		}
		if ps != nil {
			*ps = &v
			return false, nil
		}
		return false, errors.New("Union does not contain string")
	case nil:
		if nullable {
			return false, nil
		}
		return false, errors.New("Union does not contain null")
	case json.Delim:
		if v == '{' {
			if haveObject {
				return true, json.Unmarshal(data, pc)
			}
			if haveMap {
				return false, json.Unmarshal(data, pm)
			}
			return false, errors.New("Union does not contain object")
		}
		if v == '[' {
			if haveArray {
				return false, json.Unmarshal(data, pa)
			}
			return false, errors.New("Union does not contain array")
		}
		return false, errors.New("Cannot handle delimiter")
	}
	return false, errors.New("Cannot unmarshal union")
}

func marshalUnion(pi *int64, pf *float64, pb *bool, ps *string, haveArray bool, pa interface{}, haveObject bool, pc interface{}, haveMap bool, pm interface{}, haveEnum bool, pe interface{}, nullable bool) ([]byte, error) {
	if pi != nil {
		return json.Marshal(*pi)
	}
	if pf != nil {
		return json.Marshal(*pf)
	}
	if pb != nil {
		return json.Marshal(*pb)
	}
	if ps != nil {
		return json.Marshal(*ps)
	}
	if haveArray {
		return json.Marshal(pa)
	}
	if haveObject {
		return json.Marshal(pc)
	}
	if haveMap {
		return json.Marshal(pm)
	}
	if haveEnum {
		return json.Marshal(pe)
	}
	if nullable {
		return json.Marshal(nil)
	}
	return nil, errors.New("Union must not be null")
}
