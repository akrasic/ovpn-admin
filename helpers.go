package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
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
	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning(err)
		return ""
	}

	return string(content)
}

func fCreate(path string) error {
	var _, err = os.Stat(path)
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			log.Errorln(err)
			return err
		}
		defer file.Close()
	}
	return nil
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
			return err
		}
	}
	if err = os.Link(src, dst); err == nil {
		return err
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
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if basicAuth {
		req.SetBasicAuth(*masterBasicAuthUser, *masterBasicAuthPassword)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		log.Warnf("WARNING: Download file operation for url %s finished with status code %d\n", url, resp.StatusCode)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fCreate(path)
	fWrite(path, string(body))

	return nil
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

func extractFromArchive(archive, path string) error {
	// Open the file which will be written into the archive
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write file header to the tar archive
	uncompressedStream, err := gzip.NewReader(file)
	if err != nil {
		log.Fatal("extractFromArchive(): NewReader failed")
	}

	tarReader := tar.NewReader(uncompressedStream)

	for true {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatalf("extractFromArchive: Next() failed: %s", err.Error())
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(path+"/"+header.Name, 0755); err != nil {
				log.Fatalf("extractFromArchive: Mkdir() failed: %s", err.Error())
			}
		case tar.TypeReg:
			outFile, err := os.Create(path + "/" + header.Name)
			if err != nil {
				log.Fatalf("extractFromArchive: Create() failed: %s", err.Error())
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				log.Fatalf("extractFromArchive: Copy() failed: %s", err.Error())
			}
			outFile.Close()

		default:
			log.Fatalf(
				"extractFromArchive: unknown type: %c in %s", header.Typeflag, header.Name)
		}
	}
	return nil
}
