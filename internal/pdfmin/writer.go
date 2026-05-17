package pdfmin

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"sort"
)

// ObjectDef defines an object to write in an incremental update.
type ObjectDef struct {
	Obj int
	Gen int
	Val Value
}

// WriteIncremental appends an incremental update to the original PDF.
func (d *Document) WriteIncremental(objs []ObjectDef) (out []byte, objOffsets map[int]int64, xrefOffset int64, err error) {
	out = append([]byte{}, d.Raw...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}

	objOffsets = map[int]int64{}

	for _, o := range objs {
		objOffsets[o.Obj] = int64(len(out))
		out = append(out, []byte(fmt.Sprintf("%d %d obj\n", o.Obj, o.Gen))...)

		if s, ok := o.Val.(Stream); ok {
			dict := Dict{}
			for k, v := range s.StreamDict {
				dict[k] = v
			}
			dict[Name("Length")] = Int(int64(len(s.Data)))
			b, err2 := SerializeValue(dict)
			if err2 != nil {
				return nil, nil, 0, err2
			}
			out = append(out, b...)
			out = append(out, []byte("\nstream\r\n")...)
			out = append(out, s.Data...)
			out = append(out, []byte("\r\nendstream")...)
		} else {
			b, err2 := SerializeValue(o.Val)
			if err2 != nil {
				return nil, nil, 0, err2
			}
			out = append(out, b...)
		}
		out = append(out, []byte("\nendobj\n")...)
	}

	xrefOffset = int64(len(out))
	var buf bytes.Buffer
	buf.WriteString("xref\n")
	buf.WriteString("0 1\n")
	buf.WriteString("0000000000 65535 f \n")

	var nums []int
	for n := range objOffsets {
		if n == 0 {
			continue
		}
		nums = append(nums, n)
	}
	sort.Ints(nums)

	for i := 0; i < len(nums); {
		start := nums[i]
		j := i
		for j+1 < len(nums) && nums[j+1] == nums[j]+1 {
			j++
		}
		count := j - i + 1
		buf.WriteString(fmt.Sprintf("%d %d\n", start, count))
		for k := i; k <= j; k++ {
			n := nums[k]
			off := objOffsets[n]
			gen := 0
			if e, ok := d.Xref[n]; ok {
				gen = e.Gen
			}
			for _, o := range objs {
				if o.Obj == n {
					gen = o.Gen
					break
				}
			}
			buf.WriteString(fmt.Sprintf("%010d %05d n \n", off, gen))
		}
		i = j + 1
	}

	tr := Dict{}
	for k, v := range d.Trailer {
		tr[k] = v
	}
	if _, ok := tr[Name("ID")]; !ok {
		sum := md5.Sum(d.Raw)
		id := sum[:]
		tr[Name("ID")] = Array{HexBytes(id), HexBytes(id)}
	}
	tr[Name("Prev")] = Int(d.StartXref)
	maxObj := d.Size - 1
	for n := range objOffsets {
		if n > maxObj {
			maxObj = n
		}
	}
	tr[Name("Size")] = Int(maxObj + 1)

	trailerBytes, err := SerializeValue(tr)
	if err != nil {
		return nil, nil, 0, err
	}
	buf.WriteString("trailer\n")
	buf.Write(trailerBytes)
	buf.WriteString("\nstartxref\n")
	buf.WriteString(fmt.Sprintf("%d\n", xrefOffset))
	buf.WriteString("%%EOF\n")

	out = append(out, buf.Bytes()...)
	return out, objOffsets, xrefOffset, nil
}
