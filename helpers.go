package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func parseDate(layout, datetime string) time.Time {
	t, err := time.Parse(layout, datetime)
	if err != nil {
		log.Errorln(err)
	}
	return t
}

func parseDateToString(layout, datetime, format string) string {
	return parseDate(layout, datetime).Format(format)
}

func parseDateToUnix(layout, datetime string) int64 {
	return parseDate(layout, datetime).Unix()
}

// runCmd executes a command directly, without a shell. Arguments are passed as a
// slice so that user-supplied values (usernames, passwords, addresses) can never be
// interpreted as shell syntax.
//
// Nothing here may be routed through "bash -c": every argument below originates from
// an HTTP request.
func runCmd(name string, args ...string) (string, error) {
	return runCmdDir("", name, args...)
}

// runCmdDir is runCmd with a working directory, replacing "cd <dir> && ..." wrappers.
func runCmdDir(dir, name string, args ...string) (string, error) {
	return runCmdInput(dir, "", name, args...)
}

// runCmdInput is runCmdDir with data written to the command's stdin, replacing
// "echo yes | ..." wrappers.
func runCmdInput(dir, stdin, name string, args ...string) (string, error) {
	log.Debugln(name, args)
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", name, err, string(out))
	}
	return string(out), nil
}

// logCmd runs a command and logs the outcome, for call sites that historically
// discarded the result. Errors are surfaced at a visible level rather than swallowed.
func logCmd(name string, args ...string) {
	if out, err := runCmdDir("", name, args...); err != nil {
		log.Errorf("%s failed: %v", name, err)
	} else {
		log.Debug(out)
	}
}

func fExist(path string) bool {
	var _, err = os.Stat(path)

	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		// Previously log.Fatalf, which exited the daemon on a transient stat error.
		log.Errorf("fExist: %s", err)
		return false
	}

	return true
}

func fRead(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Warning(err)
		return ""
	}

	return string(content)
}

// fWrite writes content to path atomically: a temporary file in the same directory is
// written and fsynced, then renamed over the target. A failed or interrupted write
// therefore cannot leave a truncated file behind -- index.txt is the source of truth
// for every user, so a partial write there loses accounts.
func fWrite(path, content string) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("fWrite: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	defer func() {
		// No-op once the rename below has succeeded.
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("fWrite: write %s: %w", tmpName, err)
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fWrite: sync %s: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("fWrite: close %s: %w", tmpName, err)
	}
	if err = os.Chmod(tmpName, 0644); err != nil {
		return fmt.Errorf("fWrite: chmod %s: %w", tmpName, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("fWrite: rename to %s: %w", path, err)
	}

	return nil
}

func fDelete(path string) error {
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("fDelete: %s: %w", path, err)
	}
	return nil
}

func fCopy(src, dst string) error {
	sfi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories, symlinks, devices, etc.)
		return fmt.Errorf("fCopy: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("fCopy: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return nil
		}
	}
	if err = os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	err = out.Sync()
	return err
}

func fMove(src, dst string) error {
	err := fCopy(src, dst)
	if err != nil {
		log.Warn(err)
		return err
	}
	err = fDelete(src)
	if err != nil {
		log.Warn(err)
		return err
	}

	return nil
}

func fDownload(path, url string, basicAuth bool) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("fDownload: %w", err)
	}
	if basicAuth {
		req.SetBasicAuth(*masterBasicAuthUser, *masterBasicAuthPassword)
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// A non-200 body is an error page, not the file. Writing it to path anyway
	// used to hand a corrupt archive to the extraction step.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fDownload: %s returned status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return fWrite(path, string(body))
}

func createArchiveFromDir(dir, path string) error {

	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Warn(err)
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		log.Warn(err)
	}

	out, err := os.Create(path)
	if err != nil {
		log.Errorf("Error writing archive %s: %s", path, err)
		return err
	}
	defer out.Close()
	gw := gzip.NewWriter(out)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Iterate over files and add them to the tar archive
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			log.Warnf("Error writing archive %s: %s", path, err)
			return err
		}

		// Get FileInfo about our file providing file size, mode, etc.
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}

		// Create a tar Header from the FileInfo data
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			file.Close()
			return err
		}

		header.Name = strings.Replace(filePath, dir+"/", "", 1)

		// Write file header to the tar archive
		err = tw.WriteHeader(header)
		if err != nil {
			file.Close()
			return err
		}

		// Copy file content to tar archive
		_, err = io.Copy(tw, file)
		if err != nil {
			file.Close()
			return err
		}
		file.Close()
	}

	return nil
}

// extractFromArchive unpacks a tar.gz into path. Every failure is returned, not
// fatal: the archive arrives over the network from the master, and a corrupt or
// truncated download must not take the slave daemon down with it.
func extractFromArchive(archive, path string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()

	uncompressedStream, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("extractFromArchive: %s is not a gzip archive: %w", archive, err)
	}

	tarReader := tar.NewReader(uncompressedStream)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("extractFromArchive: %s: %w", archive, err)
		}

		// Entry names come off the wire, so they must not be able to address
		// anything outside the target directory ("../" and friends).
		target := filepath.Join(path, header.Name)
		if target != filepath.Clean(path) && !strings.HasPrefix(target, filepath.Clean(path)+string(os.PathSeparator)) {
			return fmt.Errorf("extractFromArchive: entry %q escapes %s", header.Name, path)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("extractFromArchive: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("extractFromArchive: %w", err)
			}
			outFile, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("extractFromArchive: %w", err)
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("extractFromArchive: %s: %w", header.Name, err)
			}
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("extractFromArchive: %w", err)
			}
		default:
			return fmt.Errorf("extractFromArchive: unsupported entry type %c for %s", header.Typeflag, header.Name)
		}
	}
	return nil
}
