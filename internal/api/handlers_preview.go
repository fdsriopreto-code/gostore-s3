package api

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "golang.org/x/image/webp" // register WebP decoding for the image pipeline

	"github.com/lojadopocket/gostore/internal/object"
)

// previewSem bounds concurrent server-side image decodes (each holds a
// full-resolution bitmap in memory).
var previewSem = make(chan struct{}, 2)

// previewMaxPixels rejects images that would decode to a huge bitmap
// (~24 MP -> ~96 MB as RGBA).
const previewMaxPixels = 24_000_000

// previewMaxDecodeBytes caps how much of an object the image endpoint will
// pull in to decode, so a huge upload can't blow memory.
const previewMaxDecodeBytes = 40 << 20

// imgParams is a parsed image-transform request.
type imgParams struct {
	w, h   int    // 0 == unconstrained on that axis
	fit    string // "contain" (default) | "cover"
	format string // "jpeg" (default) | "png"
	q      int    // JPEG quality 1..100
}

func parseImgParams(q map[string][]string) imgParams {
	p := imgParams{fit: "contain", format: "jpeg", q: 80}
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	// ?preview[=N] — legacy: N is the longest side, contain, jpeg.
	if v, ok := q["preview"]; ok {
		if len(v) > 0 && v[0] != "" {
			if n, err := strconv.Atoi(v[0]); err == nil && n >= 16 {
				p.w, p.h = n, n
			}
		}
		if p.w == 0 {
			p.w, p.h = 480, 480
		}
		return p
	}
	if n, err := strconv.Atoi(get("w")); err == nil && n > 0 {
		p.w = n
	}
	if n, err := strconv.Atoi(get("h")); err == nil && n > 0 {
		p.h = n
	}
	if p.w == 0 && p.h == 0 {
		p.w, p.h = 480, 480
	}
	if f := strings.ToLower(get("fit")); f == "cover" {
		p.fit = "cover"
	}
	if f := strings.ToLower(get("format")); f == "png" {
		p.format = "png"
	}
	if n, err := strconv.Atoi(get("q")); err == nil && n >= 1 && n <= 100 {
		p.q = n
	}
	// Hard ceilings so this can't be abused as a compute amplifier.
	if p.w > 4096 {
		p.w = 4096
	}
	if p.h > 4096 {
		p.h = 4096
	}
	return p
}

func (p imgParams) contentType() string {
	if p.format == "png" {
		return "image/png"
	}
	return "image/jpeg"
}

// cacheTag is a stable key fragment for the transform (for the RAM cache).
func (p imgParams) cacheTag() string {
	return "img:" + strconv.Itoa(p.w) + "x" + strconv.Itoa(p.h) + ":" + p.fit + ":" + p.format + ":" + strconv.Itoa(p.q)
}

// handleObjectPreview serves GET /{bucket}/{key} with ?preview[=N] or with any
// of ?w= ?h= ?fit=contain|cover ?format=jpeg|png ?q= — an on-the-fly resized
// (and optionally cropped) render of an image object. Pure stdlib. The result
// is kept in the hot-object cache keyed by the transform, so a busy image URL
// is computed once. MinIO has nothing like this.
func (s *Server) handleObjectPreview(w http.ResponseWriter, r *http.Request, bucket, key string) {
	res := "/" + bucket + "/" + key
	p := parseImgParams(r.URL.Query())

	ck := cacheKey(bucket, key, p.cacheTag())
	if r.Header.Get("Range") == "" && s.ocache.enabled() {
		if e, ok := s.ocache.get(ck); ok {
			w.Header().Set("Content-Type", p.contentType())
			w.Header().Set("Cache-Control", "private, max-age=300")
			w.Header().Set("x-gostore-cache", "HIT")
			w.Header().Set("Content-Length", strconv.Itoa(len(e.data)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(e.data)
			return
		}
	}

	// Bound concurrent decodes: a full-resolution image decode holds tens of
	// MB, and a bucket view fires many thumbnail requests at once.
	previewSem <- struct{}{}
	defer func() { <-previewSem }()

	gr, err := s.obj.GetObjectNInfo(r.Context(), bucket, key, nil, r.Header, s.vopts(bucket, r))
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), res)
		return
	}
	defer gr.Close()

	raw := make([]byte, 0, 1<<16)
	buf := make([]byte, 32<<10)
	for len(raw) <= previewMaxDecodeBytes {
		n, rerr := gr.Read(buf)
		raw = append(raw, buf[:n]...)
		if rerr != nil {
			break
		}
	}

	// Reject an image whose pixel count would blow memory when decoded
	// (DecodeConfig is header-only, cheap).
	if cfg, _, cerr := image.DecodeConfig(bytes.NewReader(raw)); cerr == nil {
		if int64(cfg.Width)*int64(cfg.Height) > previewMaxPixels {
			writeErrorResponse(w, r, ErrEntityTooLarge, res)
			return
		}
	}

	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		writeErrorResponse(w, r, ErrNotImplemented, res) // "not an image we can render"
		return
	}

	out := transformImage(src, p)
	var enc bytes.Buffer
	if p.format == "png" {
		err = png.Encode(&enc, out)
	} else {
		err = jpeg.Encode(&enc, out, &jpeg.Options{Quality: p.q})
	}
	if err != nil {
		writeErrorResponse(w, r, ErrInternalError, res)
		return
	}

	if s.ocache.enabled() && enc.Len() <= 1<<20 {
		body := append([]byte(nil), enc.Bytes()...)
		s.ocache.put(ck, body, object.ObjectInfo{
			Bucket: bucket, Name: key, Size: int64(len(body)),
			ContentType: p.contentType(), ModTime: time.Now(),
		})
	}

	w.Header().Set("Content-Type", p.contentType())
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("Content-Length", strconv.Itoa(enc.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(enc.Bytes())
}

// transformImage scales src to fit p, cropping for fit=cover.
func transformImage(src image.Image, p imgParams) image.Image {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw <= 0 || sh <= 0 {
		return src
	}
	tw, th := p.w, p.h
	if tw == 0 {
		tw = sw
	}
	if th == 0 {
		th = sh
	}

	if p.fit == "cover" && p.w > 0 && p.h > 0 {
		// Scale so the image covers the box, then centre-crop.
		scale := float64(tw) / float64(sw)
		if s2 := float64(th) / float64(sh); s2 > scale {
			scale = s2
		}
		rw := max1(int(float64(sw)*scale + 0.5))
		rh := max1(int(float64(sh)*scale + 0.5))
		scaled := boxResize(src, rw, rh)
		cx := (rw - tw) / 2
		cy := (rh - th) / 2
		dst := image.NewRGBA(image.Rect(0, 0, tw, th))
		draw.Draw(dst, dst.Bounds(), scaled, image.Pt(cx, cy), draw.Src)
		return dst
	}

	// contain: fit within the box, keep aspect ratio, no crop.
	scale := 1.0
	if p.w > 0 {
		scale = float64(tw) / float64(sw)
	}
	if p.h > 0 {
		if s2 := float64(th) / float64(sh); p.w == 0 || s2 < scale {
			scale = s2
		}
	}
	if scale > 1 {
		scale = 1 // never upscale
	}
	dw := max1(int(float64(sw)*scale + 0.5))
	dh := max1(int(float64(sh)*scale + 0.5))
	return boxResize(src, dw, dh)
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// downscale keeps the old signature (longest side <= maxDim) for any existing
// caller; it delegates to boxResize.
func downscale(src image.Image, maxDim int) image.Image {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw <= 0 || sh <= 0 {
		return src
	}
	longest := sw
	if sh > sw {
		longest = sh
	}
	scale := 1.0
	if longest > maxDim {
		scale = float64(maxDim) / float64(longest)
	}
	return boxResize(src, max1(int(float64(sw)*scale+0.5)), max1(int(float64(sh)*scale+0.5)))
}

// boxResize resizes src to exactly dw×dh using a box average (good quality for
// downscaling, which is the only case we hit — upscales are clamped away).
func boxResize(src image.Image, dw, dh int) image.Image {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if dw == sw && dh == sh {
		dst := image.NewRGBA(image.Rect(0, 0, sw, sh))
		draw.Draw(dst, dst.Bounds(), src, b.Min, draw.Src)
		return dst
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	xr := float64(sw) / float64(dw)
	yr := float64(sh) / float64(dh)
	for dy := 0; dy < dh; dy++ {
		sy0 := int(float64(dy) * yr)
		sy1 := int(float64(dy+1) * yr)
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for dx := 0; dx < dw; dx++ {
			sx0 := int(float64(dx) * xr)
			sx1 := int(float64(dx+1) * xr)
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}
			var rr, gg, bb, aa, n uint64
			for sy := sy0; sy < sy1; sy++ {
				for sx := sx0; sx < sx1; sx++ {
					cr, cg, cb, ca := src.At(b.Min.X+sx, b.Min.Y+sy).RGBA()
					rr += uint64(cr)
					gg += uint64(cg)
					bb += uint64(cb)
					aa += uint64(ca)
					n++
				}
			}
			if n == 0 {
				n = 1
			}
			dst.SetRGBA(dx, dy, color.RGBA{
				R: uint8(rr / n >> 8),
				G: uint8(gg / n >> 8),
				B: uint8(bb / n >> 8),
				A: uint8(aa / n >> 8),
			})
		}
	}
	return dst
}
