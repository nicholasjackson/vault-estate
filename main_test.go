package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateWritesAFile(t *testing.T) {
	for _, name := range []string{"startup", "noths", "scaleup", "bank", "retail-group"} {
		out := filepath.Join(t.TempDir(), name+".json")
		require.NoError(t, generate(context.Background(), []string{"-customers", "customers", "-name", name, "-out", out}))

		b, err := os.ReadFile(out)
		require.NoError(t, err)
		require.True(t, json.Valid(b), name)

		var m struct {
			Customer string `json:"customer"`
		}
		require.NoError(t, json.Unmarshal(b, &m))
		require.Equal(t, name, m.Customer)
	}

	err := generate(context.Background(), []string{"-customers", "customers", "-name", "nope"})
	require.ErrorContains(t, err, `no customer "nope"`)
}

func TestApplyNeedsAnAddressForEveryCluster(t *testing.T) {
	// a manifest of four clusters (scaleup), with an address for only one
	out := filepath.Join(t.TempDir(), "scaleup.json")
	require.NoError(t, generate(context.Background(), []string{"-customers", "customers", "-name", "scaleup", "-out", out}))

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := apply(context.Background(), []string{"-manifest", out, "-token", "root", "-addr", "scaleup=" + srv.URL})
	require.ErrorContains(t, err, "no address for cluster scaleup-lending, scaleup-payments, scaleup-platform")
	require.Zero(t, requests.Load(), "nothing is written")

	// an address for a cluster the manifest doesn't have is refused too,
	// and a closed port is never dialled
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := "http://" + l.Addr().String()
	require.NoError(t, l.Close())

	args := []string{"-manifest", out, "-token", "root"}
	for _, c := range []string{"scaleup", "scaleup-lending", "scaleup-payments", "scaleup-platform", "elsewhere"} {
		args = append(args, "-addr", c+"="+closed)
	}

	require.ErrorContains(t, apply(context.Background(), args), "the manifest has no cluster elsewhere")

	// and the flags themselves are checked
	require.ErrorContains(t, apply(context.Background(), []string{"-addr", "scaleup"}), "isn't <cluster>=<url>")
	require.ErrorContains(t, apply(context.Background(), []string{"-addr", "a=x", "-addr", "a=y"}), "more than once")
	require.ErrorContains(t, apply(context.Background(), nil), "-manifest")
}

func TestGenerateUsesTheBuiltInCustomers(t *testing.T) {
	// with no -customers, the embedded examples give the same manifest as
	// the folder they are embedded from
	builtin := filepath.Join(t.TempDir(), "builtin.json")
	require.NoError(t, generate(context.Background(), []string{"-name", "noths", "-out", builtin}))

	folder := filepath.Join(t.TempDir(), "folder.json")
	require.NoError(t, generate(context.Background(), []string{"-customers", "customers", "-name", "noths", "-out", folder}))

	a, err := os.ReadFile(builtin)
	require.NoError(t, err)
	b, err := os.ReadFile(folder)
	require.NoError(t, err)
	require.Equal(t, string(b), string(a))

	err = generate(context.Background(), nil)
	require.ErrorContains(t, err, "the built-in customers has 5 customers, pick one with -name")
}
