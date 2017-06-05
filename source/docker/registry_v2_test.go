package docker

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aybabtme/iocontrol"
	"github.com/dustin/go-humanize"
)

func TestRegistry(t *testing.T) {

	tests := []struct {
		name string
		call func(t *testing.T, ctx context.Context, reg *Registry)

		wantPath string
		wantBody []byte

		respCode int
		respBody []byte
	}{
		{
			name: "",
			call: func(t *testing.T, ctx context.Context, reg *Registry) {
				if err := reg.CheckVersion(ctx); err != nil {
					t.Fatal(err)
				}
			},
			wantPath: "/",
			wantBody: nil,
			respCode: 401,
			respBody: []byte(`{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}`),
		},

		{
			name: "",
			call: func(t *testing.T, ctx context.Context, reg *Registry) {
				if img, found, err := reg.GetImageManifest(ctx, "library/nginx", "latest"); err != nil {
					t.Fatal(err)
				} else {
					t.Errorf("found=%+v", found)
					t.Errorf("img=%+v", img)

					for _, layer := range img.Layers() {
						msw := iocontrol.NewMeasuredWriter(ioutil.Discard)
						found, err := reg.GetImageLayer(ctx, "library/nginx", layer, msw)
						if err != nil {
							t.Fatal(err)
						}
						if !found {
							t.Errorf("not found")
						} else {
							t.Errorf("pulled layer of size %s", humanize.IBytes(uint64(msw.Total())))
						}
					}
				}
			},
			wantPath: "/",
			wantBody: nil,
			respCode: 401,
			respBody: []byte(`{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(registryVersionHeader, registryVersionValue)
				w.WriteHeader(tt.respCode)
				w.Write(tt.respBody)
			}))
			defer srv.Close()

			ctx := context.Background()
			reg, err := New(ctx) //, WithBaseURL(srv.URL))
			if err != nil {
				t.Fatal(err)
			}
			tt.call(t, ctx, reg)

		})
	}
}
