package signaturepolicy

// Level represents the AdES signature level, ordered from lowest to highest,
// shared by CAdES and PAdES under the ICP-Brasil hierarchy (AD-RB → AD-RA).
type Level int

const (
	LevelB Level = iota // AD-RB: baseline / signed attributes only
	LevelT              // AD-RT: + signature timestamp
	LevelV              // AD-RV: + validation references (CAdES only)
	LevelC              // AD-RC: + validation data / DSS
	LevelA              // AD-RA: + archive timestamp
)
