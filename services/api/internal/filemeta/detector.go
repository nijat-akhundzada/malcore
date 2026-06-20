package filemeta

/*
#cgo darwin CFLAGS: -I/opt/homebrew/opt/libmagic/include -I/usr/local/include
#cgo darwin LDFLAGS: -L/opt/homebrew/opt/libmagic/lib -L/usr/local/lib -lmagic
#cgo linux LDFLAGS: -lmagic
#include <stdlib.h>
#include <magic.h>
*/
import "C"

import (
	"errors"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"unsafe"
)

type Metadata struct {
	MIMEType              string
	FileExtension         string
	MIMEExtensionMismatch bool
}

func Detect(path string, originalName string) (*Metadata, error) {
	mimeType, err := DetectMIME(path)
	if err != nil {
		return nil, err
	}

	extension := Extension(originalName)

	return &Metadata{
		MIMEType:              mimeType,
		FileExtension:         extension,
		MIMEExtensionMismatch: HasMIMEExtensionMismatch(mimeType, extension),
	}, nil
}

func DetectMIME(path string) (string, error) {
	cookie := C.magic_open(C.MAGIC_MIME_TYPE | C.MAGIC_ERROR)
	if cookie == nil {
		return "", errors.New("open libmagic")
	}
	defer C.magic_close(cookie)

	if C.magic_load(cookie, nil) != 0 {
		return "", magicError(cookie)
	}

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	result := C.magic_file(cookie, cPath)
	if result == nil {
		return "", magicError(cookie)
	}

	return C.GoString(result), nil
}

func magicError(cookie C.magic_t) error {
	err := C.magic_error(cookie)
	if err == nil {
		return errors.New("unknown libmagic error")
	}

	return errors.New(C.GoString(err))
}

func Extension(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	if parsed, err := url.Parse(name); err == nil && parsed.Path != "" {
		name = path.Base(parsed.Path)
	}

	ext := filepath.Ext(name)
	if ext == "" {
		return ""
	}

	return strings.ToLower(ext)
}

func HasMIMEExtensionMismatch(mimeType string, extension string) bool {
	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	extension = strings.ToLower(strings.TrimSpace(extension))
	if mimeType == "" || extension == "" {
		return false
	}

	allowedMIMEs, ok := expectedMIMEsByExtension[extension]
	if !ok {
		return false
	}

	for _, allowed := range allowedMIMEs {
		if mimeType == allowed {
			return false
		}
	}

	return true
}

var expectedMIMEsByExtension = map[string][]string{
	".exe": {
		"application/x-dosexec",
		"application/vnd.microsoft.portable-executable",
	},
	".dll": {
		"application/x-dosexec",
		"application/vnd.microsoft.portable-executable",
	},
	".pdf": {
		"application/pdf",
	},
	".zip": {
		"application/zip",
		"application/x-zip",
		"application/x-zip-compressed",
	},
	".js": {
		"application/javascript",
		"application/x-javascript",
		"text/javascript",
		"text/plain",
	},
	".ps1": {
		"text/plain",
		"text/x-shellscript",
	},
	".txt": {
		"text/plain",
	},
	".jpg": {
		"image/jpeg",
	},
	".jpeg": {
		"image/jpeg",
	},
	".png": {
		"image/png",
	},
	".gif": {
		"image/gif",
	},
}
