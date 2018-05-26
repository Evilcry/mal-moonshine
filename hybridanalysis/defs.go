package hybridanalysis

// URL const
// hybrid-analysis
const (
	URL = "https://www.hybrid-analysis.com/feed?json"
)

// TopLevel struct representation
// count, status and data analysis array
type TopLevel struct {
	Count  int64   `json:"count"`
	Status string  `json:"status"`
	Data   []Datum `json:"data"`
}

// Datum struct
// complete sandbox analysis representation
type Datum struct {
	Md5                    string          `json:"md5"`
	Sha1                   string          `json:"sha1"`
	Sha256                 string          `json:"sha256"`
	Isinteresting          bool            `json:"isinteresting"`
	AnalysisStartTime      string          `json:"analysis_start_time"`
	Threatscore            int64           `json:"threatscore"`
	Threatlevel            int64           `json:"threatlevel"`
	ThreatlevelHuman       string          `json:"threatlevel_human"`
	Avdetect               int64           `json:"avdetect"`
	Isunknown              bool            `json:"isunknown"`
	Vxfamily               string          `json:"vxfamily"`
	Submitname             string          `json:"submitname"`
	Isurlanalysis          bool            `json:"isurlanalysis"`
	Size                   int64           `json:"size"`
	Type                   string          `json:"type"`
	Domains                []string        `json:"domains"`
	Hosts                  []string        `json:"hosts"`
	HostsGeo               []HostsGeo      `json:"hosts_geo"`
	HostsCapped            bool            `json:"hosts_capped"`
	CompromisedHosts       []string        `json:"compromised_hosts"`
	EnvironmentID          string          `json:"environmentId"`
	EnvironmentDescription string          `json:"environmentDescription"`
	Sharedanalysis         bool            `json:"sharedanalysis"`
	Isreliable             bool            `json:"isreliable"`
	Reporturl              string          `json:"reporturl"`
	VTDetect               int64           `json:"vt_detect"`
	MSDetect               int64           `json:"ms_detect"`
	ProcessList            []ProcessList   `json:"process_list"`
	ExtractedFiles         []ExtractedFile `json:"extracted_files"`
}

// ExtractedFile struct
// extracted files
type ExtractedFile struct {
	Name                string   `json:"name"`
	FilePath            string   `json:"file_path"`
	FileSize            string   `json:"file_size"`
	Sha256              string   `json:"sha256"`
	TypeTags            []string `json:"type_tags"`
	Threatlevel         int64    `json:"threatlevel"`
	ThreatlevelReadable string   `json:"threatlevel_readable"`
}

// HostsGeo struct
// geoip information
type HostsGeo struct {
	IP  string `json:"ip"`
	Lat string `json:"lat"`
	Lon string `json:"lon"`
	Cc  string `json:"cc"`
}

// ProcessList struct
// list of involved processes
type ProcessList struct {
	Uid            string  `json:"uid"`
	Parentuid      *string `json:"parentuid"`
	Name           string  `json:"name"`
	Normalizedpath string  `json:"normalizedpath"`
	Commandline    string  `json:"commandline"`
	Sha256         string  `json:"sha256"`
	AVMatched      *int64  `json:"av_matched"`
	AVTotal        *int64  `json:"av_total"`
}
