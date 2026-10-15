package clean

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ArchiveKind classifies a path. Single-file gzip is "gz"; multi-file
// archives are "zip", "tar.gz", or "tar". Empty means not an archive.
func ArchiveKind(name string) string {
	lower := strings.ToLower(filepath.Base(name))
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar.gz"
	case strings.HasSuffix(lower, ".tar"):
		return "tar"
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".gz"):
		return "gz"
	default:
		return ""
	}
}

// IsMultiArchive reports whether name is a multi-file archive we expand,
// scan, and re-pack (zip, tar, tar.gz, tgz). Single-file .gz is not.
func IsMultiArchive(name string) bool {
	k := ArchiveKind(name)
	return k == "zip" || k == "tar.gz" || k == "tar"
}

func safeJoin(dest, name string) (string, bool) {
	target := filepath.Join(dest, name)
	cleanDest := filepath.Clean(dest)
	cleanTarget := filepath.Clean(target)
	if cleanTarget == cleanDest {
		return target, true
	}
	if strings.HasPrefix(cleanTarget+string(os.PathSeparator), cleanDest+string(os.PathSeparator)) {
		return target, true
	}
	return "", false
}

// ExtractArchive expands zip, tar, or tar.gz/tgz into dest. Returns file count.
func ExtractArchive(archive, dest string) (int, error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return 0, err
	}
	switch ArchiveKind(archive) {
	case "zip":
		return ExtractZip(archive, dest)
	case "tar.gz":
		f, err := os.Open(archive)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		zr, err := gzip.NewReader(f)
		if err != nil {
			return 0, err
		}
		defer zr.Close()
		return extractTar(zr, dest)
	case "tar":
		f, err := os.Open(archive)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return extractTar(f, dest)
	default:
		return 0, fmt.Errorf("unsupported archive: %s", archive)
	}
}

func extractTar(r io.Reader, dest string) (int, error) {
	tr := tar.NewReader(r)
	n := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		name := filepath.Clean(hdr.Name)
		if name == "." || name == "" {
			continue
		}
		target, ok := safeJoin(dest, name)
		if !ok {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return n, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return n, err
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				return n, err
			}
			if err := os.WriteFile(target, data, 0o644); err != nil {
				return n, err
			}
			n++
		}
	}
}

// WriteArchive packs srcDir as the same kind as archive (zip, tar, tar.gz).
func WriteArchive(srcDir, archive string) error {
	switch ArchiveKind(archive) {
	case "zip":
		return WriteZip(srcDir, archive)
	case "tar":
		return writeTar(srcDir, archive, false)
	case "tar.gz":
		return writeTar(srcDir, archive, true)
	default:
		return fmt.Errorf("unsupported archive output: %s", archive)
	}
}

func writeTar(srcDir, archive string, gz bool) error {
	if err := os.MkdirAll(filepath.Dir(archive), 0o755); err != nil && filepath.Dir(archive) != "." {
		return err
	}
	f, err := os.Create(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	var tw *tar.Writer
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(f)
		defer zw.Close()
		tw = tar.NewWriter(zw)
	} else {
		tw = tar.NewWriter(f)
	}
	defer tw.Close()
	files, err := walkFiles(srcDir)
	if err != nil {
		return err
	}
	for _, p := range files {
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return nil
}
