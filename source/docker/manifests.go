package docker

type ImageManifest struct {
	Name string
	Tag  string

	V1 *ImageManifestV1
	V2 *ImageManifestV2
}

// Layers returns the digest of layers of a filesystem, base first.
func (mnfst *ImageManifest) Layers() []Digest {
	var out []Digest
	if mnfst.V1 != nil {

		out = make([]Digest, len(mnfst.V1.FSLayers))
		for i, dg := range mnfst.V1.FSLayers {
			// v1 fsLayers are listed base-last
			out[len(out)-(i+1)] = dg.BlobSum
		}

	}
	if mnfst.V2 != nil {
		for _, dg := range mnfst.V2.Layers {
			out = append(out, dg.Digest)
		}
	}
	return out
}

type ImageManifestV1 struct {
	// SchemaVersion is the image manifest schema that this image follows
	SchemaVersion int `json:"schemaVersion"`

	// MediaType is the media type of this schema.
	MediaType string `json:"mediaType,omitempty"`

	// Name is the name of the image's repository
	Name string `json:"name"`

	// Tag is the tag of the image specified by this manifest
	Tag string `json:"tag"`

	// Architecture is the host architecture on which this image is intended to
	// run
	Architecture string `json:"architecture"`

	// FSLayers is a list of filesystem layer blobSums contained in this image
	FSLayers []struct {
		BlobSum Digest `json:"blobSum"`
	} `json:"fsLayers"`

	// History is a list of unstructured historical data for v1 compatibility
	History []struct {
		V1Compatibility string `json:"v1Compatibility"`
	} `json:"history"`
}

type ImageManifestV2 struct {
	// SchemaVersion is the image manifest schema that this image follows
	SchemaVersion int `json:"schemaVersion"`

	// MediaType is the media type of this schema.
	MediaType string `json:"mediaType,omitempty"`

	// Config references the image configuration as a blob.
	Config ImageManifestV2Descriptor `json:"config"`

	// Layers lists descriptors for the layers referenced by the
	// configuration.
	Layers []ImageManifestV2Descriptor `json:"layers"`
}

type ImageManifestV2Descriptor struct {
	// MediaType describe the type of the content. All text based formats are
	// encoded as utf-8.
	MediaType string `json:"mediaType,omitempty"`

	// Size in bytes of content.
	Size int64 `json:"size,omitempty"`

	// Digest uniquely identifies the content. A byte stream can be verified
	// against against this digest.
	Digest Digest `json:"digest,omitempty"`

	// URLs contains the source URLs of this content.
	URLs []string `json:"urls,omitempty"`
}
