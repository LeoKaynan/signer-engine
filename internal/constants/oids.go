package constants

var (
	// RFC5652 3 General Syntax
	OIDContentInfo = []int{1, 2, 840, 113549, 1, 9, 16, 6}

	// RFC5652 4 Data Content Type
	OIDData = []int{1, 2, 840, 113549, 1, 7, 1}

	// RFC5652 5.1  SignedData Type
	OIDSignedData = []int{1, 2, 840, 113549, 1, 7, 2}

	// RFC5652 11.1 Content Type
	OIDContentType = []int{1, 2, 840, 113549, 1, 9, 3}

	// RFC5652 11.2 Message Digest
	OIDMessageDigest = []int{1, 2, 840, 113549, 1, 9, 4}

	// RFC5652 11.3 Signing Time
	OIDSigningTime = []int{1, 2, 840, 113549, 1, 9, 5}

	// RFC4055 2.1 One-way Hash Functions
	OIDSHA1   = []int{1, 3, 14, 3, 2, 26}
	OIDSHA224 = []int{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA256 = []int{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = []int{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDSHA512 = []int{2, 16, 840, 1, 101, 3, 4, 2, 4}
)
