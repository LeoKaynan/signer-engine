package pdfmin

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// XrefEntry represents a single xref table entry.
type XrefEntry struct {
	Offset     int64
	Gen        int
	InUse      bool
	Compressed bool // true if stored in an object stream (PDF 1.5+)
	ObjStmNum  int  // object stream number (when Compressed=true)
	ObjStmIdx  int  // index within object stream (when Compressed=true)
}

// Document represents a parsed PDF.
type Document struct {
	Raw       []byte
	StartXref int64
	Xref      map[int]XrefEntry
	Trailer   Dict
	Root      IndirectRef
	Size      int
}

// ParseDocument parses a PDF from raw bytes.
func ParseDocument(raw []byte) (*Document, error) {
	startxref, err := findStartXref(raw)
	if err != nil {
		return nil, err
	}

	xref, trailer, err := parseXrefAndTrailer(raw, startxref)
	if err != nil {
		return nil, err
	}
	if _, ok := trailer[Name("Encrypt")]; ok {
		return nil, fmt.Errorf("pdfmin: encrypted PDF not supported")
	}

	root, ok := trailer.GetRef("Root")
	if !ok {
		return nil, fmt.Errorf("pdfmin: trailer missing /Root")
	}
	sizeInt, ok := trailer[Name("Size")].(Int)
	if !ok || sizeInt <= 0 {
		return nil, fmt.Errorf("pdfmin: trailer /Size invalid")
	}

	return &Document{
		Raw:       raw,
		StartXref: startxref,
		Xref:      xref,
		Trailer:   trailer,
		Root:      root,
		Size:      int(sizeInt),
	}, nil
}

// ReadIndirectObject reads an indirect object from the xref table.
func (d *Document) ReadIndirectObject(ref IndirectRef) (Value, error) {
	ent, ok := d.Xref[ref.Obj]
	if !ok || !ent.InUse {
		return nil, fmt.Errorf("pdfmin: xref does not contain obj=%d", ref.Obj)
	}
	if ent.Compressed {
		return d.readCompressedObject(ent.ObjStmNum, ent.ObjStmIdx)
	}
	return parseIndirectObjectAt(d.Raw, ent.Offset)
}

// readCompressedObject reads an object stored in an object stream (PDF 1.5+).
func (d *Document) readCompressedObject(objStmNum, idx int) (Value, error) {
	stmEntry, ok := d.Xref[objStmNum]
	if !ok || !stmEntry.InUse || stmEntry.Compressed {
		return nil, fmt.Errorf("pdfmin: object stream %d not found or invalid", objStmNum)
	}

	stmDict, streamRaw, err := parseStreamAt(d.Raw, stmEntry.Offset)
	if err != nil {
		return nil, fmt.Errorf("pdfmin: error reading object stream %d: %w", objStmNum, err)
	}

	streamData, err := decompressStream(stmDict, streamRaw)
	if err != nil {
		return nil, fmt.Errorf("pdfmin: decompress object stream %d: %w", objStmNum, err)
	}

	nVal, ok1 := stmDict[Name("N")].(Int)
	firstVal, ok2 := stmDict[Name("First")].(Int)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("pdfmin: object stream missing /N or /First")
	}
	n, first := int(nVal), int(firstVal)

	pos := 0
	offsets := make([]int, 0, n)
	for k := 0; k < n; k++ {
		pos = skipWS(streamData, pos)
		_, _, err := readInt(streamData, pos)
		if err != nil {
			return nil, fmt.Errorf("pdfmin: object stream header objnum: %w", err)
		}
		pos += lenInt(streamData, pos)
		pos = skipWS(streamData, pos)
		localOff, _, err := readInt(streamData, pos)
		if err != nil {
			return nil, fmt.Errorf("pdfmin: object stream header offset: %w", err)
		}
		offsets = append(offsets, first+int(localOff))
		pos += lenInt(streamData, pos)
	}

	if idx >= len(offsets) {
		return nil, fmt.Errorf("pdfmin: object stream index %d out of range (%d objects)", idx, len(offsets))
	}

	val, _, err := parseValue(streamData, offsets[idx])
	if err != nil {
		return nil, fmt.Errorf("pdfmin: parse object in object stream: %w", err)
	}
	return val, nil
}

// ReadCatalog returns the document catalog dict.
func (d *Document) ReadCatalog() (Dict, error) {
	v, err := d.ReadIndirectObject(d.Root)
	if err != nil {
		return nil, err
	}
	m, ok := v.(Dict)
	if !ok {
		return nil, fmt.Errorf("pdfmin: /Root is not a Dict")
	}
	return m, nil
}

// FindFirstPage finds the first page in the /Pages tree.
func (d *Document) FindFirstPage() (IndirectRef, Dict, error) {
	cat, err := d.ReadCatalog()
	if err != nil {
		return IndirectRef{}, nil, err
	}
	pagesRef, ok := cat.GetRef("Pages")
	if !ok {
		return IndirectRef{}, nil, fmt.Errorf("pdfmin: catalog missing /Pages")
	}
	return d.firstPageFromPages(pagesRef, 0)
}

func (d *Document) firstPageFromPages(pagesRef IndirectRef, depth int) (IndirectRef, Dict, error) {
	if depth > 64 {
		return IndirectRef{}, nil, fmt.Errorf("pdfmin: /Pages tree too deep")
	}
	v, err := d.ReadIndirectObject(pagesRef)
	if err != nil {
		return IndirectRef{}, nil, err
	}
	pagesDict, ok := v.(Dict)
	if !ok {
		return IndirectRef{}, nil, fmt.Errorf("pdfmin: /Pages is not a Dict")
	}
	t, _ := pagesDict.GetName("Type")
	if t == "Page" {
		return pagesRef, pagesDict, nil
	}
	kids, ok := pagesDict.GetArray("Kids")
	if !ok || len(kids) == 0 {
		return IndirectRef{}, nil, fmt.Errorf("pdfmin: /Pages missing /Kids")
	}
	first, ok := kids[0].(IndirectRef)
	if !ok {
		return IndirectRef{}, nil, fmt.Errorf("pdfmin: /Kids[0] is not a reference")
	}
	return d.firstPageFromPages(first, depth+1)
}

func findStartXref(raw []byte) (int64, error) {
	idx := bytes.LastIndex(raw, []byte("startxref"))
	if idx < 0 {
		return 0, fmt.Errorf("pdfmin: startxref not found")
	}
	i := idx + len("startxref")
	i = skipWS(raw, i)
	start, n, err := readInt(raw, i)
	if err != nil {
		return 0, fmt.Errorf("pdfmin: invalid startxref: %w", err)
	}
	_ = n
	if start < 0 || start >= int64(len(raw)) {
		return 0, fmt.Errorf("pdfmin: startxref out of file bounds: %d", start)
	}
	return start, nil
}

func parseXrefAndTrailer(raw []byte, xrefOffset int64) (map[int]XrefEntry, Dict, error) {
	i := int(xrefOffset)
	i = skipWS(raw, i)
	if bytes.HasPrefix(raw[i:], []byte("xref")) {
		return parseTraditionalXref(raw, i)
	}
	return parseXrefStream(raw, i)
}

func parseTraditionalXref(raw []byte, i int) (map[int]XrefEntry, Dict, error) {
	i += len("xref")
	xref := map[int]XrefEntry{}

	for {
		i = skipWS(raw, i)
		if bytes.HasPrefix(raw[i:], []byte("trailer")) {
			i += len("trailer")
			i = skipWS(raw, i)
			val, next, err := parseValue(raw, i)
			if err != nil {
				return nil, nil, fmt.Errorf("pdfmin: invalid trailer: %w", err)
			}
			tr, ok := val.(Dict)
			if !ok {
				return nil, nil, fmt.Errorf("pdfmin: trailer is not a Dict")
			}
			_ = next

			if prevVal, ok := tr[Name("Prev")].(Int); ok {
				prevXref, _, err := parseXrefAndTrailer(raw, int64(prevVal))
				if err == nil {
					for k, v := range prevXref {
						if _, exists := xref[k]; !exists {
							xref[k] = v
						}
					}
				}
			}

			return xref, tr, nil
		}

		startObj, _, err := readInt(raw, i)
		if err != nil {
			return nil, nil, fmt.Errorf("pdfmin: xref subsection start: %w", err)
		}
		i = skipWS(raw, i+lenInt(raw, i))
		count, _, err := readInt(raw, i)
		if err != nil {
			return nil, nil, fmt.Errorf("pdfmin: xref subsection count: %w", err)
		}
		i = skipWS(raw, i+lenInt(raw, i))

		for n := int64(0); n < count; n++ {
			i = skipWS(raw, i)
			if i+17 >= len(raw) {
				return nil, nil, fmt.Errorf("pdfmin: truncated xref line")
			}
			offStr := string(raw[i : i+10])
			genStr := string(raw[i+11 : i+16])
			inUse := raw[i+17] == 'n'
			off, err := strconv.ParseInt(offStr, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("pdfmin: xref offset: %w", err)
			}
			gen, err := strconv.Atoi(genStr)
			if err != nil {
				return nil, nil, fmt.Errorf("pdfmin: xref gen: %w", err)
			}
			xref[int(startObj+n)] = XrefEntry{Offset: off, Gen: gen, InUse: inUse}

			for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
				i++
			}
			i = skipWS(raw, i)
		}
	}
}

func parseXrefStream(raw []byte, i int) (map[int]XrefEntry, Dict, error) {
	_, _, err := readInt(raw, i)
	if err != nil {
		return nil, nil, fmt.Errorf("pdfmin: xref stream obj num: %w", err)
	}
	i += lenInt(raw, i)
	i = skipWS(raw, i)

	_, _, err = readInt(raw, i)
	if err != nil {
		return nil, nil, fmt.Errorf("pdfmin: xref stream gen: %w", err)
	}
	i += lenInt(raw, i)
	i = skipWS(raw, i)

	if !bytes.HasPrefix(raw[i:], []byte("obj")) {
		return nil, nil, fmt.Errorf("pdfmin: xref stream: expected 'obj'")
	}
	i += 3
	i = skipWS(raw, i)

	val, next, err := parseValue(raw, i)
	if err != nil {
		return nil, nil, fmt.Errorf("pdfmin: xref stream dict: %w", err)
	}
	dict, ok := val.(Dict)
	if !ok {
		return nil, nil, fmt.Errorf("pdfmin: xref stream: expected dict")
	}
	i = skipWS(raw, next)

	if !bytes.HasPrefix(raw[i:], []byte("stream")) {
		return nil, nil, fmt.Errorf("pdfmin: xref stream: expected 'stream'")
	}
	i += len("stream")
	i = skipEOL(raw, i)

	length, ok := dict[Name("Length")].(Int)
	if !ok {
		return nil, nil, fmt.Errorf("pdfmin: xref stream: invalid or missing /Length")
	}
	if i+int(length) > len(raw) {
		return nil, nil, fmt.Errorf("pdfmin: xref stream: stream truncated")
	}
	streamRaw := raw[i : i+int(length)]

	streamData, err := decompressStream(dict, streamRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("pdfmin: xref stream decompress: %w", err)
	}

	wArr, ok := dict.GetArray("W")
	if !ok || len(wArr) != 3 {
		return nil, nil, fmt.Errorf("pdfmin: xref stream: invalid /W")
	}
	var w [3]int
	for j, v := range wArr {
		if n, ok := v.(Int); ok {
			w[j] = int(n)
		}
	}
	entrySize := w[0] + w[1] + w[2]
	if entrySize == 0 {
		return nil, nil, fmt.Errorf("pdfmin: xref stream: /W sum is zero")
	}

	sizeVal, ok := dict[Name("Size")].(Int)
	if !ok {
		return nil, nil, fmt.Errorf("pdfmin: xref stream: invalid /Size")
	}

	type subsection struct{ start, count int }
	var sections []subsection
	if indexArr, ok := dict.GetArray("Index"); ok {
		if len(indexArr)%2 != 0 {
			return nil, nil, fmt.Errorf("pdfmin: xref stream: invalid /Index size")
		}
		for j := 0; j < len(indexArr); j += 2 {
			s, ok1 := indexArr[j].(Int)
			c, ok2 := indexArr[j+1].(Int)
			if !ok1 || !ok2 {
				return nil, nil, fmt.Errorf("pdfmin: xref stream: invalid /Index values")
			}
			sections = append(sections, subsection{int(s), int(c)})
		}
	} else {
		sections = []subsection{{0, int(sizeVal)}}
	}

	xref := map[int]XrefEntry{}
	pos := 0
	for _, sec := range sections {
		for n := 0; n < sec.count; n++ {
			if pos+entrySize > len(streamData) {
				break
			}
			entry := streamData[pos : pos+entrySize]
			pos += entrySize

			fieldType := 1
			if w[0] > 0 {
				fieldType = int(readBigEndian(entry[:w[0]]))
			}
			field2 := int64(0)
			if w[1] > 0 {
				field2 = int64(readBigEndian(entry[w[0] : w[0]+w[1]]))
			}
			field3 := 0
			if w[2] > 0 {
				field3 = int(readBigEndian(entry[w[0]+w[1]:]))
			}

			objNum := sec.start + n
			switch fieldType {
			case 0:
				xref[objNum] = XrefEntry{InUse: false}
			case 1:
				xref[objNum] = XrefEntry{Offset: field2, Gen: field3, InUse: true}
			case 2:
				xref[objNum] = XrefEntry{
					InUse:      true,
					Compressed: true,
					ObjStmNum:  int(field2),
					ObjStmIdx:  field3,
				}
			}
		}
	}

	if prevVal, ok := dict[Name("Prev")].(Int); ok {
		prevXref, _, err := parseXrefAndTrailer(raw, int64(prevVal))
		if err == nil {
			for k, v := range prevXref {
				if _, exists := xref[k]; !exists {
					xref[k] = v
				}
			}
		}
	}

	return xref, dict, nil
}

// parseStreamAt returns the dict and raw stream bytes of a stream object at offset.
func parseStreamAt(raw []byte, offset int64) (Dict, []byte, error) {
	i := int(offset)
	i = skipWS(raw, i)

	_, _, err := readInt(raw, i)
	if err != nil {
		return nil, nil, fmt.Errorf("pdfmin: stream obj num: %w", err)
	}
	i += lenInt(raw, i)
	i = skipWS(raw, i)

	_, _, err = readInt(raw, i)
	if err != nil {
		return nil, nil, fmt.Errorf("pdfmin: stream gen: %w", err)
	}
	i += lenInt(raw, i)
	i = skipWS(raw, i)

	if !bytes.HasPrefix(raw[i:], []byte("obj")) {
		return nil, nil, fmt.Errorf("pdfmin: stream: expected 'obj'")
	}
	i += 3
	i = skipWS(raw, i)

	val, next, err := parseValue(raw, i)
	if err != nil {
		return nil, nil, err
	}
	dict, ok := val.(Dict)
	if !ok {
		return nil, nil, fmt.Errorf("pdfmin: stream: expected dict")
	}
	i = skipWS(raw, next)

	if !bytes.HasPrefix(raw[i:], []byte("stream")) {
		return nil, nil, fmt.Errorf("pdfmin: stream: expected 'stream'")
	}
	i += len("stream")
	i = skipEOL(raw, i)

	length, ok := dict[Name("Length")].(Int)
	if !ok {
		return nil, nil, fmt.Errorf("pdfmin: stream missing /Length")
	}
	if i+int(length) > len(raw) {
		return nil, nil, fmt.Errorf("pdfmin: stream truncated")
	}
	return dict, raw[i : i+int(length)], nil
}

// decompressStream decompresses stream data based on /Filter.
func decompressStream(dict Dict, data []byte) ([]byte, error) {
	filterVal, hasFilter := dict[Name("Filter")]
	if !hasFilter {
		return data, nil
	}
	filter, ok := filterVal.(Name)
	if !ok {
		return nil, fmt.Errorf("pdfmin: /Filter is not a Name")
	}
	switch filter {
	case "FlateDecode":
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("pdfmin: FlateDecode: %w", err)
		}
		out, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return nil, fmt.Errorf("pdfmin: FlateDecode decompress: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("pdfmin: filter '%s' not supported", filter)
	}
}

// readBigEndian interprets b as a big-endian unsigned integer.
func readBigEndian(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = (v << 8) | uint64(x)
	}
	return v
}

func parseIndirectObjectAt(raw []byte, offset int64) (Value, error) {
	i := int(offset)
	i = skipWS(raw, i)
	if i >= len(raw) {
		return nil, errors.New("pdfmin: offset out of file bounds")
	}

	_, _, err := readInt(raw, i)
	if err != nil {
		return nil, fmt.Errorf("pdfmin: obj header (objnum): %w", err)
	}
	i = skipWS(raw, i+lenInt(raw, i))

	_, _, err = readInt(raw, i)
	if err != nil {
		return nil, fmt.Errorf("pdfmin: obj header (gen): %w", err)
	}
	i = skipWS(raw, i+lenInt(raw, i))

	if !bytes.HasPrefix(raw[i:], []byte("obj")) {
		return nil, fmt.Errorf("pdfmin: expected 'obj'")
	}
	i += 3
	i = skipWS(raw, i)

	val, next, err := parseValue(raw, i)
	if err != nil {
		return nil, err
	}
	i = skipWS(raw, next)

	if bytes.HasPrefix(raw[i:], []byte("stream")) {
		for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
			i++
		}
		i = skipEOL(raw, i)
		end := bytes.Index(raw[i:], []byte("endstream"))
		if end < 0 {
			return nil, fmt.Errorf("pdfmin: stream missing endstream")
		}
	}

	return val, nil
}

func parseValue(raw []byte, i int) (Value, int, error) {
	i = skipWS(raw, i)
	if i >= len(raw) {
		return nil, i, fmt.Errorf("pdfmin: unexpected EOF")
	}

	if bytes.HasPrefix(raw[i:], []byte("<<")) {
		i += 2
		d := Dict{}
		for {
			i = skipWS(raw, i)
			if i >= len(raw) {
				return nil, i, fmt.Errorf("pdfmin: EOF in dict")
			}
			if bytes.HasPrefix(raw[i:], []byte(">>")) {
				i += 2
				return d, i, nil
			}
			if raw[i] != '/' {
				return nil, i, fmt.Errorf("pdfmin: expected Name in dict, got=%q", raw[i])
			}
			key, next, err := parseName(raw, i)
			if err != nil {
				return nil, i, err
			}
			i = skipWS(raw, next)
			val, next2, err := parseValue(raw, i)
			if err != nil {
				return nil, i, err
			}
			d[key] = val
			i = next2
		}
	}

	if raw[i] == '[' {
		i++
		var a Array
		for {
			i = skipWS(raw, i)
			if i >= len(raw) {
				return nil, i, fmt.Errorf("pdfmin: EOF in array")
			}
			if raw[i] == ']' {
				i++
				return a, i, nil
			}
			v, next, err := parseValue(raw, i)
			if err != nil {
				return nil, i, err
			}
			a = append(a, v)
			i = next
		}
	}

	if raw[i] == '(' {
		s, next, err := parseLiteralString(raw, i)
		return String(s), next, err
	}

	if raw[i] == '<' && (i+1 < len(raw) && raw[i+1] != '<') {
		hb, next, err := parseHexString(raw, i)
		return HexBytes(hb), next, err
	}

	if raw[i] == '/' {
		n, next, err := parseName(raw, i)
		return n, next, err
	}

	if bytes.HasPrefix(raw[i:], []byte("null")) {
		return Null{}, i + 4, nil
	}
	if bytes.HasPrefix(raw[i:], []byte("true")) {
		return Boolean(true), i + 4, nil
	}
	if bytes.HasPrefix(raw[i:], []byte("false")) {
		return Boolean(false), i + 5, nil
	}

	if isNumStart(raw[i]) {
		first, _, err := readInt(raw, i)
		if err == nil {
			afterFirst := i + lenInt(raw, i)
			j := skipWS(raw, afterFirst)
			if j < len(raw) && isNumStart(raw[j]) {
				_, _, err2 := readInt(raw, j)
				if err2 == nil {
					k := skipWS(raw, j+lenInt(raw, j))
					if k < len(raw) && raw[k] == 'R' {
						second, _, _ := readInt(raw, j)
						return IndirectRef{Obj: int(first), Gen: int(second)}, k + 1, nil
					}
				}
			}
			return Int(first), afterFirst, nil
		}
		f, next, err := readReal(raw, i)
		if err == nil {
			return Real(f), next, nil
		}
	}

	return nil, i, fmt.Errorf("pdfmin: unexpected token at %d (byte=%q)", i, raw[i])
}

func parseName(raw []byte, i int) (Name, int, error) {
	if raw[i] != '/' {
		return "", i, fmt.Errorf("pdfmin: expected '/'")
	}
	i++
	start := i
	for i < len(raw) && !isWS(raw[i]) && !isDelimiter(raw[i]) {
		i++
	}
	return Name(raw[start:i]), i, nil
}

func parseLiteralString(raw []byte, i int) (string, int, error) {
	if raw[i] != '(' {
		return "", i, fmt.Errorf("pdfmin: expected '('")
	}
	i++
	var out bytes.Buffer
	depth := 1
	for i < len(raw) {
		c := raw[i]
		i++
		if c == '\\' {
			if i >= len(raw) {
				return "", i, fmt.Errorf("pdfmin: escape at EOF")
			}
			out.WriteByte(raw[i])
			i++
			continue
		}
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 {
				return out.String(), i, nil
			}
		}
		out.WriteByte(c)
	}
	return "", i, fmt.Errorf("pdfmin: string missing ')'")
}

func parseHexString(raw []byte, i int) ([]byte, int, error) {
	if raw[i] != '<' {
		return nil, i, fmt.Errorf("pdfmin: expected '<'")
	}
	i++
	start := i
	for i < len(raw) && raw[i] != '>' {
		i++
	}
	if i >= len(raw) {
		return nil, i, fmt.Errorf("pdfmin: hex string missing '>'")
	}
	hexStr := bytes.TrimSpace(raw[start:i])
	i++
	hexStr = bytes.ReplaceAll(hexStr, []byte("\n"), nil)
	hexStr = bytes.ReplaceAll(hexStr, []byte("\r"), nil)
	hexStr = bytes.ReplaceAll(hexStr, []byte("\t"), nil)
	hexStr = bytes.ReplaceAll(hexStr, []byte(" "), nil)
	if len(hexStr)%2 == 1 {
		hexStr = append(hexStr, '0')
	}
	out := make([]byte, len(hexStr)/2)
	if _, err := hex.Decode(out, hexStr); err != nil {
		return nil, i, fmt.Errorf("pdfmin: invalid hex: %w", err)
	}
	return out, i, nil
}

func readInt(raw []byte, i int) (int64, int, error) {
	start := i
	if i < len(raw) && (raw[i] == '+' || raw[i] == '-') {
		i++
	}
	for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
		i++
	}
	if i == start || (i == start+1 && (raw[start] == '+' || raw[start] == '-')) {
		return 0, 0, fmt.Errorf("pdfmin: invalid int")
	}
	v, err := strconv.ParseInt(string(raw[start:i]), 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return v, i - start, nil
}

func readReal(raw []byte, i int) (float64, int, error) {
	start := i
	if i < len(raw) && (raw[i] == '+' || raw[i] == '-') {
		i++
	}
	hasDot := false
	for i < len(raw) {
		if raw[i] >= '0' && raw[i] <= '9' {
			i++
			continue
		}
		if raw[i] == '.' && !hasDot {
			hasDot = true
			i++
			continue
		}
		break
	}
	if i == start {
		return 0, 0, fmt.Errorf("pdfmin: invalid real")
	}
	v, err := strconv.ParseFloat(string(raw[start:i]), 64)
	if err != nil {
		return 0, 0, err
	}
	return v, i, nil
}

func lenInt(raw []byte, i int) int {
	_, n, err := readInt(raw, i)
	if err != nil {
		return 0
	}
	return n
}

func skipWS(raw []byte, i int) int {
	for i < len(raw) {
		c := raw[i]
		if isWS(c) {
			i++
			continue
		}
		if c == '%' {
			for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
				i++
			}
			continue
		}
		break
	}
	return i
}

func skipEOL(raw []byte, i int) int {
	if i < len(raw) && raw[i] == '\r' {
		i++
		if i < len(raw) && raw[i] == '\n' {
			i++
		}
		return i
	}
	if i < len(raw) && raw[i] == '\n' {
		return i + 1
	}
	return i
}

func isWS(c byte) bool {
	switch c {
	case 0x00, 0x09, 0x0A, 0x0C, 0x0D, 0x20:
		return true
	default:
		return false
	}
}

func isDelimiter(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	default:
		return false
	}
}

func isNumStart(c byte) bool {
	return (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
}
