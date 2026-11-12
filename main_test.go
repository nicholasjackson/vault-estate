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
		require.NoError(t, generate(context.Background(), []string{filepath.Join("examples", name+".xcl"), "-out", out}))

		b, err := os.ReadFile(out)
		require.NoError(t, err)
		require.True(t, json.Valid(b), name)

		var m struct {
			Customer string `json:"customer"`
		}
		require.NoError(t, json.Unmarshal(b, &m))
		require.Equal(t, name, m.Customer)
	}

	err := generate(context.Background(), []string{"examples", "-name", "nope"})
	require.ErrorContains(t, err, `no customer "nope"`)
}

func TestApplyNeedsAnAddressForEveryCluster(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")

	// a manifest of four clusters (scaleup), with an address for only one
	out := filepath.Join(t.TempDir(), "scaleup.json")
	require.NoError(t, generate(context.Background(), []string{"examples/scaleup.xcl", "-out", out}))

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

func TestGenerateTakesAnXCLFileOrFolder(t *testing.T) {
	// a customer from its file, flags before or after it, and from the
	// examples folder by name, give the same manifest
	var manifests []string
	for _, args := range [][]string{
		{"examples/noths.xcl"},
		{"-name", "noths", "examples"},
		{"examples", "-name", "noths"},
	} {
		out := filepath.Join(t.TempDir(), "noths.json")
		require.NoError(t, generate(context.Background(), append(args, "-out", out)), args)

		b, err := os.ReadFile(out)
		require.NoError(t, err)
		manifests = append(manifests, string(b))
	}

	require.Equal(t, manifests[0], manifests[1])
	require.Equal(t, manifests[0], manifests[2])

	// a folder of more than one customer needs -name
	require.ErrorContains(t, generate(context.Background(), []string{"examples"}), "examples has 5 customers, pick one with -name")

	// and the file or folder is required, once
	require.ErrorContains(t, generate(context.Background(), nil), "give the customer's xcl file or folder")
	require.ErrorContains(t, show(context.Background(), nil), "vault-estate show examples/noths.xcl")
	require.ErrorContains(t, show(context.Background(), []string{"examples/noths.xcl", "examples/bank.xcl"}), "give one xcl file or folder, not 2")
}

func TestApplyTakesTheAddressFromVaultAddr(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)

	// a manifest of one cluster (startup) is applied to $VAULT_ADDR
	startup := filepath.Join(t.TempDir(), "startup.json")
	require.NoError(t, generate(context.Background(), []string{"examples/startup.xcl", "-out", startup}))

	err := apply(context.Background(), []string{"-manifest", startup, "-token", "root"})
	require.Error(t, err, "the fake Vault fails every request")
	require.NotContains(t, err.Error(), "no address")
	require.NotZero(t, requests.Load(), "$VAULT_ADDR is used")

	// -addr wins over $VAULT_ADDR
	requests.Store(0)
	var flagged atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flagged.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer other.Close()

	require.Error(t, apply(context.Background(), []string{"-manifest", startup, "-token", "root", "-addr", "startup=" + other.URL}))
	require.NotZero(t, flagged.Load(), "-addr is used")
	require.Zero(t, requests.Load(), "$VAULT_ADDR isn't used")

	// and a manifest of more than one cluster (scaleup) still needs -addr
	scaleup := filepath.Join(t.TempDir(), "scaleup.json")
	require.NoError(t, generate(context.Background(), []string{"examples/scaleup.xcl", "-out", scaleup}))

	err = apply(context.Background(), []string{"-manifest", scaleup, "-token", "root"})
	require.ErrorContains(t, err, "$VAULT_ADDR is one address, but the manifest has 4 clusters")
	require.Zero(t, requests.Load(), "nothing is written")
}
