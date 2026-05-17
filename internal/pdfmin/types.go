// Package pdfmin provides minimal PDF parsing and incremental update writing.
package pdfmin

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Value represents a basic PDF value.
type Value interface {
	isPDFValue()
}

type (
	Null     struct{}
	Boolean  bool
	Name     string
	Int      int64
	Real     float64
	String   string
	HexBytes []byte
	Raw      string

	Array []Value
	Dict  map[Name]Value

	// Stream represents a PDF stream object with a dictionary and binary data.
	// /Length is computed automatically from len(Data).
	Stream struct {
		StreamDict Dict   // dictionary entries (without /Length)
		Data       []byte // uncompressed stream content
	}
)

// IndirectRef is a PDF indirect object reference.
type IndirectRef struct {
	Obj int
	Gen int
}

func (Null) isPDFValue()        {}
func (Boolean) isPDFValue()     {}
func (Name) isPDFValue()        {}
func (Int) isPDFValue()         {}
func (Real) isPDFValue()        {}
func (String) isPDFValue()      {}
func (HexBytes) isPDFValue()    {}
func (Raw) isPDFValue()         {}
func (Array) isPDFValue()       {}
func (Dict) isPDFValue()        {}
func (IndirectRef) isPDFValue() {}
func (Stream) isPDFValue()      {}

func (d Dict) GetName(key string) (Name, bool) {
	v, ok := d[Name(key)]
	if !ok {
		return "", false
	}
	n, ok := v.(Name)
	return n, ok
}

func (d Dict) GetRef(key string) (IndirectRef, bool) {
	v, ok := d[Name(key)]
	if !ok {
		return IndirectRef{}, false
	}
	r, ok := v.(IndirectRef)
	return r, ok
}

func (d Dict) GetDict(key string) (Dict, bool) {
	v, ok := d[Name(key)]
	if !ok {
		return nil, false
	}
	m, ok := v.(Dict)
	return m, ok
}

func (d Dict) GetArray(key string) (Array, bool) {
	v, ok := d[Name(key)]
	if !ok {
		return nil, false
	}
	a, ok := v.(Array)
	return a, ok
}

func (d Dict) Set(key string, v Value) {
	if d == nil {
		return
	}
	d[Name(key)] = v
}

// SerializeValue converts a Value to PDF bytes.
func SerializeValue(v Value) ([]byte, error) {
	var b bytes.Buffer
	if err := writeValue(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeValue(b *bytes.Buffer, v Value) error {
	switch x := v.(type) {
	case Null:
		b.WriteString("null")
	case Boolean:
		if bool(x) {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case Name:
		b.WriteByte('/')
		b.WriteString(string(x))
	case Int:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case Real:
		b.WriteString(strconv.FormatFloat(float64(x), 'f', -1, 64))
	case String:
		s := strings.ReplaceAll(string(x), `\`, `\\`)
		s = strings.ReplaceAll(s, "(", `\(`)
		s = strings.ReplaceAll(s, ")", `\)`)
		b.WriteByte('(')
		b.WriteString(s)
		b.WriteByte(')')
	case HexBytes:
		b.WriteByte('<')
		enc := make([]byte, hex.EncodedLen(len(x)))
		hex.Encode(enc, []byte(x))
		b.Write(bytes.ToUpper(enc))
		b.WriteByte('>')
	case Raw:
		b.WriteString(string(x))
	case Array:
		b.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				b.WriteByte(' ')
			}
			if err := writeValue(b, it); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case Dict:
		b.WriteString("<<")
		for k, it := range x {
			b.WriteByte(' ')
			b.WriteByte('/')
			b.WriteString(string(k))
			b.WriteByte(' ')
			if err := writeValue(b, it); err != nil {
				return err
			}
		}
		b.WriteString(" >>")
	case IndirectRef:
		b.WriteString(strconv.Itoa(x.Obj))
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(x.Gen))
		b.WriteString(" R")
	default:
		return fmt.Errorf("pdfmin: unsupported type: %T", v)
	}
	return nil
}
