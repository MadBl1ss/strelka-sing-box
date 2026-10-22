package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
)

// The tray icon is a shield drawn at startup and tinted per state, so there
// are no .ico assets to ship alongside the binary.
var shield = [][2]float64{{16, 1}, {30, 8}, {30, 17}, {16, 31}, {2, 17}, {2, 8}}

func inPoly(x, y float64, pts [][2]float64) bool {
	in := false
	n := len(pts)
	j := n - 1
	for i := 0; i < n; i++ {
		xi, yi := pts[i][0], pts[i][1]
		xj, yj := pts[j][0], pts[j][1]
		if (yi > y) != (yj > y) && x < (xj-xi)*(y-yi)/(yj-yi)+xi {
			in = !in
		}
		j = i
	}
	return in
}

// shrink pulls the polygon toward its centroid, giving the darker border ring.
func shrink(pts [][2]float64, f float64) [][2]float64 {
	var cx, cy float64
	for _, p := range pts {
		cx += p[0]
		cy += p[1]
	}
	cx /= float64(len(pts))
	cy /= float64(len(pts))
	out := make([][2]float64, len(pts))
	for i, p := range pts {
		out[i] = [2]float64{cx + (p[0]-cx)*f, cy + (p[1]-cy)*f}
	}
	return out
}

// makeIcon renders the shield to a 32x32 PNG, wrapped as ICO on Windows by
// iconBytes. NRGBA keeps colours straight (not alpha-premultiplied), which
// is what the PNG encoder wants.
func makeIcon(fill, edge color.NRGBA) []byte {
	const size, ss = 32, 4
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	inner := shrink(shield, 0.80)

	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, hits float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := float64(px) + (float64(sx)+0.5)/ss
					y := float64(py) + (float64(sy)+0.5)/ss
					if !inPoly(x, y, shield) {
						continue
					}
					c := edge
					if inPoly(x, y, inner) {
						c = fill
					}
					r += float64(c.R)
					g += float64(c.G)
					b += float64(c.B)
					hits++
				}
			}
			if hits == 0 {
				continue
			}
			// Colour is averaged over covered samples; alpha is the coverage.
			cov := hits / float64(ss*ss)
			img.SetNRGBA(px, py, color.NRGBA{
				R: uint8(r / hits),
				G: uint8(g / hits),
				B: uint8(b / hits),
				A: uint8(cov * 255),
			})
		}
	}

	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		return nil
	}
	return iconBytes(pngBuf.Bytes(), size)
}

// icoWrap puts a PNG inside a single-entry ICO container. Windows has
// accepted PNG-compressed icon entries since Vista.
func icoWrap(pngData []byte, size int) []byte {
	buf := new(bytes.Buffer)
	w := func(v any) { binary.Write(buf, binary.LittleEndian, v) }

	w(uint16(0)) // reserved
	w(uint16(1)) // type: icon
	w(uint16(1)) // image count

	buf.WriteByte(byte(size)) // width  (0 would mean 256)
	buf.WriteByte(byte(size)) // height
	buf.WriteByte(0)          // palette size
	buf.WriteByte(0)          // reserved
	w(uint16(1))              // colour planes
	w(uint16(32))             // bits per pixel
	w(uint32(len(pngData)))   // payload size
	w(uint32(22))             // payload offset: 6 + 16

	buf.Write(pngData)
	return buf.Bytes()
}

var icons = map[string][]byte{
	"ok":    makeIcon(color.NRGBA{46, 204, 113, 255}, color.NRGBA{24, 120, 66, 255}),
	"warn":  makeIcon(color.NRGBA{241, 196, 15, 255}, color.NRGBA{140, 110, 10, 255}),
	"error": makeIcon(color.NRGBA{231, 76, 60, 255}, color.NRGBA{130, 40, 32, 255}),
	"off":   makeIcon(color.NRGBA{130, 140, 150, 255}, color.NRGBA{70, 78, 86, 255}),
}
