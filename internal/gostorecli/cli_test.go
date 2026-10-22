package gostorecli_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lojadopocket/gostore/internal/api"
	"github.com/lojadopocket/gostore/internal/bucketcfg"
	"github.com/lojadopocket/gostore/internal/config"
	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/event"
	"github.com/lojadopocket/gostore/internal/gostorecli"
	"github.com/lojadopocket/gostore/internal/iam"
	fsb "github.com/lojadopocket/gostore/internal/object/fs"
)

func TestCLIEndToEnd(t *testing.T) {
	be, err := fsb.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Region = "us-east-1"
	dir := t.TempDir()
	im, _ := iam.New("cliadmin", "cliadmin-secret", configstore.NewDir(dir), nil)
	bc, _ := bucketcfg.Open(configstore.NewDir(dir))
	srv := httptest.NewServer(api.NewServer(cfg, be, im, bc, event.New(bc), nil, nil))
	defer srv.Close()

	aliasFile := filepath.Join(t.TempDir(), "aliases.json")
	t.Setenv("GOSTORE_ALIAS_FILE", aliasFile)

	run := func(args ...string) {
		t.Helper()
		if code := gostorecli.Run(args); code != 0 {
			t.Fatalf("gostore %v -> exit %d", args, code)
		}
	}

	run("alias", "set", "t", srv.URL, "cliadmin", "cliadmin-secret")
	run("mb", "t/clibucket")

	// Upload a local file, download it back, compare.
	src := filepath.Join(t.TempDir(), "hello.txt")
	if err := os.WriteFile(src, []byte("hello from the cli"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("cp", src, "t/clibucket/greeting.txt")

	dstDir := t.TempDir()
	run("cp", "t/clibucket/greeting.txt", dstDir+"/")
	got, err := os.ReadFile(filepath.Join(dstDir, "greeting.txt"))
	if err != nil || string(got) != "hello from the cli" {
		t.Fatalf("round-trip via CLI: %q %v", got, err)
	}

	run("stat", "t/clibucket/greeting.txt")
	run("ls", "t/clibucket")
	run("rm", "t/clibucket/greeting.txt")
	run("admin", "info", "t")
	run("bench", "t/clibucket", "--duration", "1s", "--size", "4KiB", "--concurrency", "4")

	// A bad alias credential must fail.
	run("alias", "set", "bad", srv.URL, "cliadmin", "wrong-secret")
	if code := gostorecli.Run([]string{"ls", "bad/clibucket"}); code == 0 {
		t.Fatal("ls with a wrong secret should fail")
	}
}
