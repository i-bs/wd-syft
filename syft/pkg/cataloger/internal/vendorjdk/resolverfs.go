/*
Package vendorjdk is the glue between syft's file.Resolver and the runtime detector of the shared osv-internal module
(github.com/bell-sw/osv-internal/vendorjdk): it adapts a resolver to the io/fs.FS the detector reads, caches verdicts
per runtime home, and carries the "apk-managed runtime" rule of the vendor distributions.
*/
package vendorjdk

import (
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

// FS adapts a file.Resolver to io/fs.FS (plus StatFS, ReadDirFS and ReadFileFS). Names are in fs.FS notation
// ("opt/jdk-21.0.2/release"); they are looked up as absolute resolver paths.
type FS struct {
	Resolver file.Resolver
}

var (
	_ fs.FS         = (*FS)(nil)
	_ fs.StatFS     = (*FS)(nil)
	_ fs.ReadDirFS  = (*FS)(nil)
	_ fs.ReadFileFS = (*FS)(nil)
)

// NewFS wraps a resolver.
func NewFS(resolver file.Resolver) *FS {
	return &FS{Resolver: resolver}
}

// ToFSName converts a resolver path to fs.FS notation.
func ToFSName(p string) string {
	p = path.Clean("/" + p)
	if p == "/" {
		return "."
	}
	return strings.TrimPrefix(p, "/")
}

// ToResolverPath converts an fs.FS name to the absolute path resolvers use.
func ToResolverPath(name string) string {
	if name == "." || name == "" {
		return "/"
	}
	return "/" + strings.TrimPrefix(name, "/")
}

func (f *FS) location(name string) (*file.Location, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	locs, err := f.Resolver.FilesByPath(ToResolverPath(name))
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	if len(locs) == 0 {
		return nil, nil
	}
	return &locs[0], nil
}

func (f *FS) Open(name string) (fs.File, error) {
	loc, err := f.location(name)
	if err != nil {
		return nil, err
	}
	if loc == nil {
		if f.Resolver.HasPath(ToResolverPath(name)) || name == "." {
			return &dirFile{fsys: f, name: name}, nil
		}
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	meta, err := f.Resolver.FileMetadataByLocation(*loc)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	rc, err := f.Resolver.FileContentsByLocation(*loc)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &resolverFile{name: name, rc: rc, info: fileInfo{name: path.Base(name), meta: meta}}, nil
}

func (f *FS) Stat(name string) (fs.FileInfo, error) {
	loc, err := f.location(name)
	if err != nil {
		return nil, err
	}
	if loc == nil {
		if f.Resolver.HasPath(ToResolverPath(name)) || name == "." {
			return dirInfo{name: path.Base(name)}, nil
		}
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	meta, err := f.Resolver.FileMetadataByLocation(*loc)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	return fileInfo{name: path.Base(name), meta: meta}, nil
}

func (f *FS) ReadFile(name string) ([]byte, error) {
	fh, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return io.ReadAll(fh)
}

// ReadDir lists the immediate children of a directory: files from the resolver plus directories derived from the
// paths below them (resolvers index files only).
func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	base := ToResolverPath(name)
	if base != "/" && !f.Resolver.HasPath(base) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	locs, err := f.Resolver.FilesByGlob(path.Join(base, "**"))
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	prefix := strings.TrimSuffix(base, "/") + "/"
	seen := map[string]fs.DirEntry{}
	for _, loc := range locs {
		// directory sources report paths relative to the scanned root, images absolute ones
		real := "/" + strings.TrimPrefix(loc.RealPath, "/")
		rel := strings.TrimPrefix(real, prefix)
		if rel == real || rel == "" {
			continue
		}
		child, rest, isDir := strings.Cut(rel, "/")
		if _, ok := seen[child]; ok {
			continue
		}
		if isDir && rest != "" {
			seen[child] = dirInfo{name: child}
			continue
		}
		meta, err := f.Resolver.FileMetadataByLocation(loc)
		if err != nil {
			continue
		}
		seen[child] = fs.FileInfoToDirEntry(fileInfo{name: child, meta: meta})
	}
	var out []fs.DirEntry
	for _, e := range seen {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

type resolverFile struct {
	name string
	rc   io.ReadCloser
	info fileInfo
	ra   unionreader.UnionReader
}

func (r *resolverFile) Read(p []byte) (int, error) {
	if r.ra != nil {
		return r.ra.Read(p)
	}
	return r.rc.Read(p)
}

// ReadAt is served through a union reader (seekable when the resolver supports it, buffered otherwise).
func (r *resolverFile) ReadAt(p []byte, off int64) (int, error) {
	if r.ra == nil {
		ur, err := unionreader.GetUnionReader(r.rc)
		if err != nil {
			return 0, err
		}
		r.ra = ur
	}
	return r.ra.ReadAt(p, off)
}

func (r *resolverFile) Seek(offset int64, whence int) (int64, error) {
	if r.ra == nil {
		ur, err := unionreader.GetUnionReader(r.rc)
		if err != nil {
			return 0, err
		}
		r.ra = ur
	}
	return r.ra.Seek(offset, whence)
}

func (r *resolverFile) Stat() (fs.FileInfo, error) { return r.info, nil }

func (r *resolverFile) Close() error {
	if r.ra != nil {
		return r.ra.Close()
	}
	return r.rc.Close()
}

type fileInfo struct {
	name string
	meta file.Metadata
}

func (i fileInfo) Name() string { return i.name }
func (i fileInfo) Size() int64 {
	if i.meta.FileInfo != nil {
		return i.meta.Size()
	}
	return 0
}
func (i fileInfo) Mode() fs.FileMode {
	if i.meta.FileInfo != nil {
		return i.meta.Mode()
	}
	return 0o644
}
func (i fileInfo) ModTime() time.Time {
	if i.meta.FileInfo != nil {
		return i.meta.ModTime()
	}
	return time.Time{}
}
func (i fileInfo) IsDir() bool { return false }
func (i fileInfo) Sys() any    { return nil }

type dirInfo struct{ name string }

func (d dirInfo) Name() string               { return d.name }
func (d dirInfo) Size() int64                { return 0 }
func (d dirInfo) Mode() fs.FileMode          { return fs.ModeDir | 0o755 }
func (d dirInfo) ModTime() time.Time         { return time.Time{} }
func (d dirInfo) IsDir() bool                { return true }
func (d dirInfo) Sys() any                   { return nil }
func (d dirInfo) Type() fs.FileMode          { return fs.ModeDir }
func (d dirInfo) Info() (fs.FileInfo, error) { return d, nil }

type dirFile struct {
	fsys    *FS
	name    string
	entries []fs.DirEntry
	offset  int
}

func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errors.New("is a directory")}
}
func (d *dirFile) Stat() (fs.FileInfo, error) { return dirInfo{name: path.Base(d.name)}, nil }
func (d *dirFile) Close() error               { return nil }
func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.entries == nil {
		entries, err := d.fsys.ReadDir(d.name)
		if err != nil {
			return nil, err
		}
		d.entries = entries
	}
	rest := d.entries[d.offset:]
	if n <= 0 {
		d.offset = len(d.entries)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	if n > len(rest) {
		n = len(rest)
	}
	d.offset += n
	return rest[:n], nil
}
