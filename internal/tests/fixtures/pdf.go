package fixtures

import (
	"fmt"
	"strings"
)

// MinimalPDF returns a minimal valid PDF document with dynamically computed
// xref offsets. Suitable for signing tests.
func MinimalPDF() []byte {
	var sb strings.Builder
	offsets := make([]int64, 4)

	sb.WriteString("%PDF-1.4\n")

	offsets[1] = int64(sb.Len())
	sb.WriteString("1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n")

	offsets[2] = int64(sb.Len())
	sb.WriteString("2 0 obj\n<</Type /Pages /Kids [3 0 R] /Count 1>>\nendobj\n")

	offsets[3] = int64(sb.Len())
	sb.WriteString("3 0 obj\n<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>\nendobj\n")

	xrefOffset := int64(sb.Len())
	sb.WriteString("xref\n")
	sb.WriteString("0 4\n")
	sb.WriteString("0000000000 65535 f \n")
	for i := 1; i < 4; i++ {
		sb.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i]))
	}
	sb.WriteString("trailer\n")
	sb.WriteString("<</Size 4 /Root 1 0 R>>\n")
	sb.WriteString("startxref\n")
	sb.WriteString(fmt.Sprintf("%d\n", xrefOffset))
	sb.WriteString("%%EOF\n")

	return []byte(sb.String())
}
