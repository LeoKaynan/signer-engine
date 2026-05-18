package pades

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"signer-engine/internal/pdfmin"
)

const (
	// placeholderSizeBase is the /Contents hex placeholder size for AD-RB signatures.
	// Each byte becomes 2 hex chars, so this reserves 8 KiB of signature space.
	placeholderSizeBase = 16384

	// placeholderSizeTimestamp reserves 16 KiB for signatures with embedded timestamps.
	placeholderSizeTimestamp = 32768

	// placeholderSizeDocTS reserves 16 KiB for document timestamp tokens.
	placeholderSizeDocTS = 32768

	maxSignRetries = 5
	maxDocTSRetries = 5

	pdfFilter          = "Adobe.PPKLite"
	pdfSubFilter       = "adbe.pkcs7.detached"
	pdfSubFilterRFC3161 = "ETSI.RFC3161"

	defaultFieldName     = "Signature1"
	docMDPPermission     = 2
	reservedSerialFields = 3
)

// byteRangePlaceholder is the fixed-length string used as a /ByteRange placeholder.
// It is replaced in-place once the actual byte offsets are known, so its length
// must be exactly len("/ByteRange [0000000000 0000000000 0000000000 0000000000]").
const byteRangePlaceholder = "/ByteRange [0000000000 0000000000 0000000000 0000000000]"

var rePDFField = regexp.MustCompile(`/T\s*\(([^)]*)\)`)

type signOptions struct {
	PlaceholderSize int
	FieldName       string
	SignerName       string
	Reason          string
	ReuseEmptyField bool
	ReserveFields   int
	SigningTime      time.Time
}

type preparedField struct {
	ref    pdfmin.IndirectRef
	dict   pdfmin.Dict
	gen    int
	widget pdfmin.IndirectRef
}

// buildPDFWithPlaceholder appends an incremental update that adds a signature
// field with a /Contents hex placeholder and a /ByteRange placeholder.
// contentsStart is the byte offset of the '<', contentsEnd of the '>' + 1.
func buildPDFWithPlaceholder(pdfBytes []byte, opts signOptions) (out []byte, contentsStart, contentsEnd int64, err error) {
	doc, err := pdfmin.ParseDocument(pdfBytes)
	if err != nil {
		return nil, 0, 0, err
	}

	catalog, err := doc.ReadCatalog()
	if err != nil {
		return nil, 0, 0, err
	}
	pageRef, pageDict, err := doc.FindFirstPage()
	if err != nil {
		return nil, 0, 0, err
	}

	nextObj := findNextObjNum(doc)
	shouldSetDocMDP := !catalogHasDocMDP(catalog)

	sigRef := pdfmin.IndirectRef{Obj: nextObj, Gen: 0}
	nextObj++

	placeholder := make([]byte, opts.PlaceholderSize)
	sigDict := pdfmin.Dict{
		pdfmin.Name("Type"):   pdfmin.Name("Sig"),
		pdfmin.Name("Filter"): pdfmin.Name(pdfFilter),
		pdfmin.Name("SubFilter"): pdfmin.Name(pdfSubFilter),
		pdfmin.Name("ByteRange"): pdfmin.Array{
			pdfmin.Raw("0000000000"),
			pdfmin.Raw("0000000000"),
			pdfmin.Raw("0000000000"),
			pdfmin.Raw("0000000000"),
		},
		pdfmin.Name("Contents"): pdfmin.HexBytes(placeholder),
		pdfmin.Name("M"):        pdfmin.String(formatPDFDate(opts.SigningTime)),
	}
	if opts.SignerName != "" {
		sigDict[pdfmin.Name("Name")] = pdfmin.String(opts.SignerName)
	}
	if opts.Reason != "" {
		sigDict[pdfmin.Name("Reason")] = pdfmin.String(opts.Reason)
	}
	if shouldSetDocMDP {
		sigDict[pdfmin.Name("Reference")] = pdfmin.Array{
			pdfmin.Dict{
				pdfmin.Name("Type"):            pdfmin.Name("SigRef"),
				pdfmin.Name("TransformMethod"): pdfmin.Name("DocMDP"),
				pdfmin.Name("TransformParams"): pdfmin.Dict{
					pdfmin.Name("Type"): pdfmin.Name("TransformParams"),
					pdfmin.Name("P"):    pdfmin.Int(docMDPPermission),
					pdfmin.Name("V"):    pdfmin.Name("1.2"),
				},
			},
		}
	}

	var updatedAnnotsObj *pdfmin.ObjectDef
	pageChanged := false

	var acroFormObjNum int
	var acroFormGen int
	var acroFormDict pdfmin.Dict
	createdAcroForm := false
	if r, ok := catalog.GetRef("AcroForm"); ok {
		acroFormObjNum = r.Obj
		if e, ok := doc.Xref[r.Obj]; ok {
			acroFormGen = e.Gen
		}
		v, err2 := doc.ReadIndirectObject(r)
		if err2 != nil {
			return nil, 0, 0, fmt.Errorf("pades: error reading AcroForm: %w", err2)
		}
		m, ok := v.(pdfmin.Dict)
		if !ok {
			return nil, 0, 0, fmt.Errorf("pades: AcroForm is not a dict")
		}
		acroFormDict = m
	} else {
		acroFormObjNum = nextObj
		acroFormRef := pdfmin.IndirectRef{Obj: acroFormObjNum, Gen: 0}
		nextObj++
		acroFormDict = pdfmin.Dict{}
		catalog[pdfmin.Name("AcroForm")] = acroFormRef
		createdAcroForm = true
	}

	var fields pdfmin.Array
	var fieldsRef pdfmin.IndirectRef
	var fieldsRefGen int
	var updatedFieldsObj *pdfmin.ObjectDef
	if existing, ok := acroFormDict.GetArray("Fields"); ok {
		fields = append(pdfmin.Array{}, existing...)
	} else if existingRef, ok := acroFormDict.GetRef("Fields"); ok {
		v, err2 := doc.ReadIndirectObject(existingRef)
		if err2 != nil {
			return nil, 0, 0, fmt.Errorf("pades: error reading Fields: %w", err2)
		}
		arr, ok := v.(pdfmin.Array)
		if !ok {
			return nil, 0, 0, fmt.Errorf("pades: Fields is not an array")
		}
		fields = append(pdfmin.Array{}, arr...)
		fieldsRef = existingRef
		fieldsRefGen = existingRef.Gen
		if e, ok := doc.Xref[existingRef.Obj]; ok {
			fieldsRefGen = e.Gen
		}
	} else {
		fields = pdfmin.Array{}
	}

	var activeField preparedField
	var additionalFields []preparedField
	if opts.ReuseEmptyField {
		activeField, err = findReusableSignatureField(doc, fields, opts.FieldName)
		if err != nil {
			return nil, 0, 0, err
		}
		activeField.dict[pdfmin.Name("V")] = sigRef
	} else {
		fieldName := opts.FieldName
		if fieldName == "" || fieldName == defaultFieldName {
			fieldName = nextSignatureFieldName(pdfBytes)
		}
		activeField, nextObj = createSignatureFieldObject(nextObj, pageRef, fieldName, sigRef)
		fields = append(fields, activeField.ref)
	}

	if shouldSetDocMDP && opts.ReserveFields > 0 {
		seed := append([]byte{}, pdfBytes...)
		seed = append(seed, []byte("/T ("+fieldNameOf(activeField.dict)+")")...)
		for _, name := range nextSignatureFieldNames(seed, opts.ReserveFields) {
			var reserve preparedField
			reserve, nextObj = createEmptySignatureFieldObject(nextObj, pageRef, name)
			fields = append(fields, reserve.ref)
			additionalFields = append(additionalFields, reserve)
			seed = append(seed, []byte("/T ("+name+")")...)
		}
	}

	var widgetRefs pdfmin.Array
	if !opts.ReuseEmptyField {
		widgetRefs = append(widgetRefs, activeField.widget)
	}
	for _, field := range additionalFields {
		widgetRefs = append(widgetRefs, field.widget)
	}
	if len(widgetRefs) > 0 {
		if annots, ok := pageDict.GetArray("Annots"); ok {
			pageDict[pdfmin.Name("Annots")] = append(annots, widgetRefs...)
			pageChanged = true
		} else if annRef, ok := pageDict.GetRef("Annots"); ok {
			v, err2 := doc.ReadIndirectObject(annRef)
			if err2 != nil {
				return nil, 0, 0, fmt.Errorf("pades: error reading Annots: %w", err2)
			}
			arr, ok := v.(pdfmin.Array)
			if !ok {
				return nil, 0, 0, fmt.Errorf("pades: Annots is not an array")
			}
			arr = append(arr, widgetRefs...)
			gen := annRef.Gen
			if e, ok := doc.Xref[annRef.Obj]; ok {
				gen = e.Gen
			}
			updatedAnnotsObj = &pdfmin.ObjectDef{Obj: annRef.Obj, Gen: gen, Val: arr}
		} else {
			pageDict[pdfmin.Name("Annots")] = widgetRefs
			pageChanged = true
		}
	}

	catalogChanged := createdAcroForm
	if shouldSetDocMDP {
		catalog[pdfmin.Name("Perms")] = pdfmin.Dict{
			pdfmin.Name("DocMDP"): sigRef,
		}
		catalogChanged = true
	}

	acroFormChanged := createdAcroForm
	if fieldsRef.Obj > 0 {
		if !opts.ReuseEmptyField || len(additionalFields) > 0 {
			updatedFieldsObj = &pdfmin.ObjectDef{Obj: fieldsRef.Obj, Gen: fieldsRefGen, Val: fields}
		}
		if createdAcroForm {
			acroFormDict[pdfmin.Name("Fields")] = fieldsRef
			acroFormChanged = true
		}
	} else {
		if createdAcroForm || !opts.ReuseEmptyField || len(additionalFields) > 0 {
			acroFormDict[pdfmin.Name("Fields")] = fields
			acroFormChanged = true
		}
	}
	if createdAcroForm || !opts.ReuseEmptyField || len(additionalFields) > 0 {
		if current, ok := acroFormDict[pdfmin.Name("SigFlags")].(pdfmin.Int); !ok || current != pdfmin.Int(3) {
			acroFormDict[pdfmin.Name("SigFlags")] = pdfmin.Int(3)
			acroFormChanged = true
		}
	}

	var objs []pdfmin.ObjectDef

	if catalogChanged {
		gen := doc.Root.Gen
		if e, ok := doc.Xref[doc.Root.Obj]; ok {
			gen = e.Gen
		}
		objs = append(objs, pdfmin.ObjectDef{Obj: doc.Root.Obj, Gen: gen, Val: catalog})
	}

	if pageChanged {
		gen := pageRef.Gen
		if e, ok := doc.Xref[pageRef.Obj]; ok {
			gen = e.Gen
		}
		objs = append(objs, pdfmin.ObjectDef{Obj: pageRef.Obj, Gen: gen, Val: pageDict})
	}

	if acroFormChanged {
		objs = append(objs, pdfmin.ObjectDef{Obj: acroFormObjNum, Gen: acroFormGen, Val: acroFormDict})
	}
	if updatedFieldsObj != nil {
		objs = append(objs, *updatedFieldsObj)
	}
	if updatedAnnotsObj != nil {
		objs = append(objs, *updatedAnnotsObj)
	}

	objs = append(objs, pdfmin.ObjectDef{Obj: sigRef.Obj, Gen: sigRef.Gen, Val: sigDict})
	objs = append(objs, pdfmin.ObjectDef{Obj: activeField.ref.Obj, Gen: activeField.gen, Val: activeField.dict})
	if !opts.ReuseEmptyField {
		objs = append(objs, pdfmin.ObjectDef{
			Obj: activeField.widget.Obj,
			Gen: activeField.widget.Gen,
			Val: buildSignatureWidgetDict(pageRef, activeField.ref),
		})
	}
	for _, field := range additionalFields {
		objs = append(objs,
			pdfmin.ObjectDef{Obj: field.ref.Obj, Gen: field.gen, Val: field.dict},
			pdfmin.ObjectDef{Obj: field.widget.Obj, Gen: field.widget.Gen, Val: buildSignatureWidgetDict(pageRef, field.ref)},
		)
	}

	out, _, _, err = doc.WriteIncremental(objs)
	if err != nil {
		return nil, 0, 0, err
	}

	cs, ce, err := findLastContentsRange(out)
	if err != nil {
		return nil, 0, 0, err
	}
	return out, cs, ce, nil
}

// patchLastByteRange replaces the /ByteRange placeholder with the actual byte
// offsets that exclude the /Contents hex value.
func patchLastByteRange(pdf []byte, contentsStart, contentsEnd int64) ([]byte, error) {
	placeholder := []byte(byteRangePlaceholder)
	fileLen := int64(len(pdf))
	final := []byte(fmt.Sprintf("/ByteRange [%010d %010d %010d %010d]",
		0, contentsStart, contentsEnd, fileLen-contentsEnd))
	if len(final) != len(placeholder) {
		return nil, fmt.Errorf("pades: ByteRange patch length mismatch: got %d want %d", len(final), len(placeholder))
	}
	idx := bytes.LastIndex(pdf, placeholder)
	if idx < 0 {
		return nil, fmt.Errorf("pades: ByteRange placeholder not found")
	}
	out := append([]byte{}, pdf...)
	copy(out[idx:idx+len(final)], final)
	return out, nil
}

// patchLastContents encodes sigDER as uppercase hex and writes it into the last
// /Contents placeholder. Returns ok=false if the signature is larger than the
// placeholder (caller should retry with a bigger placeholder).
func patchLastContents(pdf []byte, sigDER []byte) (out []byte, ok bool, err error) {
	ltAbs, gtAbs, err := findLastContentsPositions(pdf)
	if err != nil {
		return nil, false, err
	}
	innerStart := ltAbs + 1
	innerEnd := gtAbs
	capacity := innerEnd - innerStart
	sigHex := bytes.ToUpper([]byte(hex.EncodeToString(sigDER)))
	if len(sigHex) > capacity {
		return nil, false, nil
	}
	out = append([]byte{}, pdf...)
	for len(sigHex) < capacity {
		sigHex = append(sigHex, '0')
	}
	copy(out[innerStart:innerEnd], sigHex)
	return out, true, nil
}

func findLastContentsRange(pdf []byte) (contentsStart, contentsEnd int64, err error) {
	lt, gt, err := findLastContentsPositions(pdf)
	if err != nil {
		return 0, 0, err
	}
	return int64(lt), int64(gt + 1), nil
}

func findLastContentsPositions(pdf []byte) (lt, gt int, err error) {
	idx := bytes.LastIndex(pdf, []byte("/Contents <"))
	if idx < 0 {
		return 0, 0, fmt.Errorf("pades: /Contents not found")
	}
	ltRel := bytes.IndexByte(pdf[idx:], '<')
	if ltRel < 0 {
		return 0, 0, fmt.Errorf("pades: '<' not found after /Contents")
	}
	ltAbs := idx + ltRel
	gtRel := bytes.IndexByte(pdf[ltAbs:], '>')
	if gtRel < 0 {
		return 0, 0, fmt.Errorf("pades: '>' not found after /Contents '<'")
	}
	return ltAbs, ltAbs + gtRel, nil
}

func buildSignatureWidgetDict(pageRef, fieldRef pdfmin.IndirectRef) pdfmin.Dict {
	return pdfmin.Dict{
		pdfmin.Name("Type"):    pdfmin.Name("Annot"),
		pdfmin.Name("Subtype"): pdfmin.Name("Widget"),
		pdfmin.Name("Rect"):    pdfmin.Array{pdfmin.Int(0), pdfmin.Int(0), pdfmin.Int(0), pdfmin.Int(0)},
		pdfmin.Name("F"):       pdfmin.Int(4),
		pdfmin.Name("P"):       pageRef,
		pdfmin.Name("Parent"):  fieldRef,
	}
}

func createSignatureFieldObject(nextObj int, pageRef pdfmin.IndirectRef, fieldName string, sigRef pdfmin.IndirectRef) (preparedField, int) {
	fieldRef := pdfmin.IndirectRef{Obj: nextObj, Gen: 0}
	nextObj++
	widgetRef := pdfmin.IndirectRef{Obj: nextObj, Gen: 0}
	nextObj++
	return preparedField{
		ref: fieldRef,
		dict: pdfmin.Dict{
			pdfmin.Name("FT"):   pdfmin.Name("Sig"),
			pdfmin.Name("T"):    pdfmin.String(fieldName),
			pdfmin.Name("V"):    sigRef,
			pdfmin.Name("Kids"): pdfmin.Array{widgetRef},
		},
		gen:    fieldRef.Gen,
		widget: widgetRef,
	}, nextObj
}

func createEmptySignatureFieldObject(nextObj int, _ pdfmin.IndirectRef, fieldName string) (preparedField, int) {
	fieldRef := pdfmin.IndirectRef{Obj: nextObj, Gen: 0}
	nextObj++
	widgetRef := pdfmin.IndirectRef{Obj: nextObj, Gen: 0}
	nextObj++
	return preparedField{
		ref: fieldRef,
		dict: pdfmin.Dict{
			pdfmin.Name("FT"):   pdfmin.Name("Sig"),
			pdfmin.Name("T"):    pdfmin.String(fieldName),
			pdfmin.Name("Kids"): pdfmin.Array{widgetRef},
		},
		gen:    fieldRef.Gen,
		widget: widgetRef,
	}, nextObj
}

func findReusableSignatureField(doc *pdfmin.Document, fields pdfmin.Array, preferredName string) (preparedField, error) {
	trimmed := strings.TrimSpace(preferredName)
	var fallback *preparedField
	for _, item := range fields {
		ref, ok := item.(pdfmin.IndirectRef)
		if !ok {
			continue
		}
		value, err := doc.ReadIndirectObject(ref)
		if err != nil {
			return preparedField{}, fmt.Errorf("pades: error reading signature field: %w", err)
		}
		fieldDict, ok := value.(pdfmin.Dict)
		if !ok {
			continue
		}
		if ft, _ := fieldDict.GetName("FT"); ft != "Sig" {
			continue
		}
		if _, hasValue := fieldDict[pdfmin.Name("V")]; hasValue {
			continue
		}
		name := fieldNameOf(fieldDict)
		field := preparedField{ref: ref, dict: fieldDict, gen: ref.Gen}
		if e, ok := doc.Xref[ref.Obj]; ok {
			field.gen = e.Gen
		}
		if kids, ok := fieldDict.GetArray("Kids"); ok && len(kids) > 0 {
			if widgetRef, ok := kids[0].(pdfmin.IndirectRef); ok {
				field.widget = widgetRef
			}
		}
		if trimmed != "" && name == trimmed {
			return field, nil
		}
		if fallback == nil {
			f := field
			fallback = &f
		}
	}
	if trimmed != "" {
		return preparedField{}, fmt.Errorf("pades: empty signature field not found: %s", trimmed)
	}
	if fallback == nil {
		return preparedField{}, fmt.Errorf("pades: no empty pre-allocated signature field available for serial operation")
	}
	return *fallback, nil
}

func fieldNameOf(field pdfmin.Dict) string {
	if raw, ok := field[pdfmin.Name("T")]; ok {
		if name, ok := raw.(pdfmin.String); ok {
			return string(name)
		}
	}
	return ""
}

// IsAlreadySigned reports whether pdfBytes contains at least one PAdES signature
// (detected by the presence of a DocMDP entry in the catalog Perms dictionary,
// which is set by the first PAdES signature).
func IsAlreadySigned(pdfBytes []byte) (bool, error) {
	doc, err := pdfmin.ParseDocument(pdfBytes)
	if err != nil {
		return false, fmt.Errorf("pades: parse PDF: %w", err)
	}
	catalog, err := doc.ReadCatalog()
	if err != nil {
		return false, fmt.Errorf("pades: read catalog: %w", err)
	}
	return catalogHasDocMDP(catalog), nil
}

func catalogHasDocMDP(catalog pdfmin.Dict) bool {
	if catalog == nil {
		return false
	}
	if ref, ok := catalog.GetRef("Perms"); ok && ref.Obj > 0 {
		return true
	}
	if perms, ok := catalog.GetDict("Perms"); ok {
		if _, ok := perms.GetRef("DocMDP"); ok {
			return true
		}
		if _, ok := perms[pdfmin.Name("DocMDP")]; ok {
			return true
		}
	}
	return false
}

func findNextObjNum(doc *pdfmin.Document) int {
	maxObj := 0
	for n := range doc.Xref {
		if n > maxObj {
			maxObj = n
		}
	}
	if doc.Size-1 > maxObj {
		maxObj = doc.Size - 1
	}
	return maxObj + 1
}

func formatPDFDate(t time.Time) string {
	return fmt.Sprintf("D:%04d%02d%02d%02d%02d%02dZ",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}

func nextSignatureFieldName(pdf []byte) string {
	return nextSignatureFieldNames(pdf, 1)[0]
}

func nextSignatureFieldNames(pdf []byte, count int) []string {
	used := map[string]struct{}{}
	matches := rePDFField.FindAllSubmatch(pdf, -1)
	for _, match := range matches {
		if len(match) > 1 {
			used[string(match[1])] = struct{}{}
		}
	}
	names := make([]string, 0, count)
	if _, exists := used[defaultFieldName]; !exists {
		names = append(names, defaultFieldName)
		used[defaultFieldName] = struct{}{}
	}
	for idx := 2; len(names) < count; idx++ {
		candidate := fmt.Sprintf("Signature%d", idx)
		if _, exists := used[candidate]; exists {
			continue
		}
		names = append(names, candidate)
		used[candidate] = struct{}{}
	}
	return names
}

// addDSS appends an incremental update containing a DSS (Document Security Store)
// with the provided cert and CRL DERs indexed by the VRI key of the last signature.
// Returns the updated PDF and the VRI key (used later to link the DocTimeStamp into the VRI entry).
func addDSS(signedPDF []byte, certDERs [][]byte, crlDERs [][]byte, signingTime time.Time, pbad *PBADArtifacts) ([]byte, string, error) {
	vriKey, err := computeVRIKey(signedPDF)
	if err != nil {
		return nil, "", err
	}

	doc, err := pdfmin.ParseDocument(signedPDF)
	if err != nil {
		return nil, "", fmt.Errorf("pades: parse PDF for DSS: %w", err)
	}

	catalog, err := doc.ReadCatalog()
	if err != nil {
		return nil, "", fmt.Errorf("pades: read catalog for DSS: %w", err)
	}

	nextObj := findNextObjNum(doc)
	var objs []pdfmin.ObjectDef

	certObjs, certRefs := buildDERStreamObjects(certDERs, &nextObj)
	objs = append(objs, certObjs...)

	crlObjs, crlRefs := buildDERStreamObjects(crlDERs, &nextObj)
	objs = append(objs, crlObjs...)

	var (
		pbadPolicyRef pdfmin.IndirectRef
		pbadLpaARef   pdfmin.IndirectRef
		pbadLpaSRef   pdfmin.IndirectRef
		hasPBAD       bool
	)
	if pbad != nil && len(pbad.PolicyArtifact) > 0 && len(pbad.LpaArtifact) > 0 && len(pbad.LpaSignature) > 0 {
		hasPBAD = true

		policyObjs, policyRefs := buildDERStreamObjects([][]byte{pbad.PolicyArtifact}, &nextObj)
		objs = append(objs, policyObjs...)
		pbadPolicyRef = policyRefs[0].(pdfmin.IndirectRef)

		lpaAObjs, lpaARefs := buildDERStreamObjects([][]byte{pbad.LpaArtifact}, &nextObj)
		objs = append(objs, lpaAObjs...)
		pbadLpaARef = lpaARefs[0].(pdfmin.IndirectRef)

		lpaSObjs, lpaSRefs := buildDERStreamObjects([][]byte{pbad.LpaSignature}, &nextObj)
		objs = append(objs, lpaSObjs...)
		pbadLpaSRef = lpaSRefs[0].(pdfmin.IndirectRef)
	}

	vriEntry := pdfmin.Dict{
		pdfmin.Name("Type"): pdfmin.Name("VRI"),
		pdfmin.Name("Cert"): certRefs,
		pdfmin.Name("CRL"):  crlRefs,
		pdfmin.Name("TU"):   pdfmin.String(formatPDFDate(signingTime)),
	}
	if hasPBAD {
		vriEntry[pdfmin.Name("PBAD_PolicyArtifact")] = pbadPolicyRef
		vriEntry[pdfmin.Name("PBAD_LpaArtifact")] = pbadLpaARef
		vriEntry[pdfmin.Name("PBAD_LpaSignature")] = pbadLpaSRef
	}

	dssDict := pdfmin.Dict{
		pdfmin.Name("Type"):  pdfmin.Name("DSS"),
		pdfmin.Name("Certs"): certRefs,
		pdfmin.Name("CRLs"):  crlRefs,
		pdfmin.Name("VRI"): pdfmin.Dict{
			pdfmin.Name(vriKey): vriEntry,
		},
	}
	if hasPBAD {
		dssDict[pdfmin.Name("PBAD_PolicyArtifacts")] = pdfmin.Array{pbadPolicyRef}
		dssDict[pdfmin.Name("PBAD_LpaArtifacts")] = pdfmin.Array{pbadLpaARef}
		dssDict[pdfmin.Name("PBAD_LpaSignatures")] = pdfmin.Array{pbadLpaSRef}
	}

	dssRef := pdfmin.IndirectRef{Obj: nextObj, Gen: 0}
	nextObj++
	objs = append(objs, pdfmin.ObjectDef{Obj: dssRef.Obj, Gen: dssRef.Gen, Val: dssDict})

	catalog[pdfmin.Name("DSS")] = dssRef
	if e, ok := doc.Xref[doc.Root.Obj]; ok {
		objs = append(objs, pdfmin.ObjectDef{Obj: doc.Root.Obj, Gen: e.Gen, Val: catalog})
	} else {
		objs = append(objs, pdfmin.ObjectDef{Obj: doc.Root.Obj, Gen: doc.Root.Gen, Val: catalog})
	}

	result, _, _, err := doc.WriteIncremental(objs)
	if err != nil {
		return nil, "", fmt.Errorf("pades: incremental update with DSS: %w", err)
	}

	return result, vriKey, nil
}

// addDocumentTimestamp appends an incremental update containing a DocTimeStamp field.
// stampFn receives the bytes outside /Contents and returns the RFC 3161 token DER.
// Retries with a larger placeholder if the token does not fit.
func addDocumentTimestamp(pdf []byte, fieldName string, stampFn func([]byte) ([]byte, error)) ([]byte, error) {
	size := placeholderSizeDocTS
	for attempt := 0; attempt < maxDocTSRetries; attempt++ {
		result, ok, err := tryAddDocumentTimestamp(pdf, fieldName, size, stampFn)
		if err != nil {
			return nil, err
		}
		if ok {
			return result, nil
		}
		size *= 2
	}
	return nil, fmt.Errorf("pades: document timestamp did not fit in placeholder after %d retries", maxDocTSRetries)
}

func tryAddDocumentTimestamp(pdf []byte, fieldName string, placeholderSize int, stampFn func([]byte) ([]byte, error)) ([]byte, bool, error) {
	doc, err := pdfmin.ParseDocument(pdf)
	if err != nil {
		return nil, false, fmt.Errorf("pades: parse PDF for DocTimeStamp: %w", err)
	}

	catalog, err := doc.ReadCatalog()
	if err != nil {
		return nil, false, fmt.Errorf("pades: read catalog for DocTimeStamp: %w", err)
	}

	nextObj := findNextObjNum(doc)

	placeholder := make([]byte, placeholderSize)
	tsDict := pdfmin.Dict{
		pdfmin.Name("Type"):      pdfmin.Name("DocTimeStamp"),
		pdfmin.Name("Filter"):    pdfmin.Name(pdfFilter),
		pdfmin.Name("SubFilter"): pdfmin.Name(pdfSubFilterRFC3161),
		pdfmin.Name("ByteRange"): pdfmin.Array{
			pdfmin.Raw("0000000000"),
			pdfmin.Raw("0000000000"),
			pdfmin.Raw("0000000000"),
			pdfmin.Raw("0000000000"),
		},
		pdfmin.Name("Contents"): pdfmin.HexBytes(placeholder),
	}

	tsRef := pdfmin.IndirectRef{Obj: nextObj, Gen: 0}
	nextObj++
	fieldRef := pdfmin.IndirectRef{Obj: nextObj, Gen: 0}
	nextObj++

	actualFieldName := nextAvailableDocTSFieldName(doc.Raw, fieldName)
	fieldObj := pdfmin.ObjectDef{
		Obj: fieldRef.Obj,
		Gen: fieldRef.Gen,
		Val: pdfmin.Dict{
			pdfmin.Name("FT"): pdfmin.Name("Sig"),
			pdfmin.Name("T"):  pdfmin.String(actualFieldName),
			pdfmin.Name("V"):  tsRef,
		},
	}

	var objs []pdfmin.ObjectDef
	acroFormObj, updatedFieldsObj, err := appendFieldToAcroForm(doc, catalog, fieldRef)
	if err != nil {
		return nil, false, err
	}
	if acroFormObj.Obj > 0 {
		objs = append(objs, acroFormObj)
	}
	if updatedFieldsObj.Obj > 0 {
		objs = append(objs, updatedFieldsObj)
	}
	objs = append(objs, fieldObj)
	objs = append(objs, pdfmin.ObjectDef{Obj: tsRef.Obj, Gen: 0, Val: tsDict})

	out, _, _, err := doc.WriteIncremental(objs)
	if err != nil {
		return nil, false, fmt.Errorf("pades: write DocTimeStamp incremental update: %w", err)
	}

	ltAbs, gtAbs, err := findLastContentsPositions(out)
	if err != nil {
		return nil, false, fmt.Errorf("pades: find Contents for DocTimeStamp: %w", err)
	}
	cs, ce := int64(ltAbs), int64(gtAbs+1)

	out, err = patchLastByteRange(out, cs, ce)
	if err != nil {
		return nil, false, fmt.Errorf("pades: patch ByteRange for DocTimeStamp: %w", err)
	}

	toStamp := make([]byte, 0, len(out)-int(ce-cs))
	toStamp = append(toStamp, out[:cs]...)
	toStamp = append(toStamp, out[ce:]...)

	token, err := stampFn(toStamp)
	if err != nil {
		return nil, false, fmt.Errorf("pades: request document timestamp: %w", err)
	}

	result, ok, err := patchLastContents(out, token)
	if err != nil {
		return nil, false, fmt.Errorf("pades: patch DocTimeStamp Contents: %w", err)
	}
	return result, ok, nil
}

// buildDERStreamObjects creates PDF stream objects from DER-encoded items.
// Returns the object definitions and an array of indirect references.
func buildDERStreamObjects(items [][]byte, nextObj *int) ([]pdfmin.ObjectDef, pdfmin.Array) {
	var objs []pdfmin.ObjectDef
	var refs pdfmin.Array
	for _, item := range items {
		ref := pdfmin.IndirectRef{Obj: *nextObj, Gen: 0}
		(*nextObj)++
		objs = append(objs, pdfmin.ObjectDef{
			Obj: ref.Obj,
			Gen: ref.Gen,
			Val: pdfmin.Stream{Data: item},
		})
		refs = append(refs, ref)
	}
	return objs, refs
}

// computeVRIKey returns the uppercase hex SHA-1 of the decoded /Contents bytes
// of the most recent signature. Per ISO 32000-2 §12.8.4.3 / ETSI TS 102 778-4 §4.3.2.
func computeVRIKey(pdf []byte) (string, error) {
	ltAbs, gtAbs, err := findLastContentsPositions(pdf)
	if err != nil {
		return "", fmt.Errorf("pades: find /Contents for VRI key: %w", err)
	}
	contentBytes, err := hex.DecodeString(string(pdf[ltAbs+1 : gtAbs]))
	if err != nil {
		return "", fmt.Errorf("pades: decode /Contents for VRI key: %w", err)
	}
	h := sha1.Sum(contentBytes)
	return fmt.Sprintf("%X", h), nil
}

func nextAvailableDocTSFieldName(pdf []byte, base string) string {
	if strings.TrimSpace(base) == "" {
		base = "DocTimeStamp"
	}
	used := map[string]struct{}{}
	matches := rePDFField.FindAllSubmatch(pdf, -1)
	for _, match := range matches {
		if len(match) > 1 {
			used[string(match[1])] = struct{}{}
		}
	}
	if _, exists := used[base]; !exists {
		return base
	}
	for idx := 2; ; idx++ {
		candidate := fmt.Sprintf("%s%d", base, idx)
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
}

// appendFieldToAcroForm updates the AcroForm dictionary to include fieldRef.
// Returns updated object definitions (zero-value Obj means nothing to write).
func appendFieldToAcroForm(doc *pdfmin.Document, catalog pdfmin.Dict, fieldRef pdfmin.IndirectRef) (pdfmin.ObjectDef, pdfmin.ObjectDef, error) {
	if catalog == nil {
		return pdfmin.ObjectDef{}, pdfmin.ObjectDef{}, nil
	}
	ref, ok := catalog.GetRef("AcroForm")
	if !ok {
		return pdfmin.ObjectDef{}, pdfmin.ObjectDef{}, nil
	}

	value, err := doc.ReadIndirectObject(ref)
	if err != nil {
		return pdfmin.ObjectDef{}, pdfmin.ObjectDef{}, fmt.Errorf("pades: read AcroForm for DocTimeStamp: %w", err)
	}
	acroFormDict, ok := value.(pdfmin.Dict)
	if !ok {
		return pdfmin.ObjectDef{}, pdfmin.ObjectDef{}, fmt.Errorf("pades: AcroForm is not a dict")
	}

	gen := ref.Gen
	if e, ok := doc.Xref[ref.Obj]; ok {
		gen = e.Gen
	}

	var updatedFieldsObj pdfmin.ObjectDef
	if fields, ok := acroFormDict.GetArray("Fields"); ok {
		acroFormDict[pdfmin.Name("Fields")] = append(fields, fieldRef)
	} else if fieldsRef, ok := acroFormDict.GetRef("Fields"); ok {
		fv, err := doc.ReadIndirectObject(fieldsRef)
		if err != nil {
			return pdfmin.ObjectDef{}, pdfmin.ObjectDef{}, fmt.Errorf("pades: read Fields for DocTimeStamp: %w", err)
		}
		arr, ok := fv.(pdfmin.Array)
		if !ok {
			return pdfmin.ObjectDef{}, pdfmin.ObjectDef{}, fmt.Errorf("pades: Fields is not an array")
		}
		fieldsGen := fieldsRef.Gen
		if e, ok := doc.Xref[fieldsRef.Obj]; ok {
			fieldsGen = e.Gen
		}
		updatedFieldsObj = pdfmin.ObjectDef{Obj: fieldsRef.Obj, Gen: fieldsGen, Val: append(arr, fieldRef)}
	} else {
		acroFormDict[pdfmin.Name("Fields")] = pdfmin.Array{fieldRef}
	}

	acroFormDict[pdfmin.Name("SigFlags")] = pdfmin.Int(3)
	return pdfmin.ObjectDef{Obj: ref.Obj, Gen: gen, Val: acroFormDict}, updatedFieldsObj, nil
}
