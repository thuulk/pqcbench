package main

import (
	//"errors"
	"log"
	"os"
	"os/exec"
)


func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}


/** Runs a command showing its output, and stops the orchestrator if it fails */
func run(name string, args ...string) {
        cmd := exec.Command(name, args...)
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        if err := cmd.Run(); err != nil {
                log.Fatalf("%s %v: %v", name, args, err)
        }
}


/** Setting up the benchmark dir and files if they are not set already */
func setup() {
	info, err := os.Stat("results")
	notDir := !(err == nil && info.IsDir()) 

	if notDir {
		run("mkdir", "results")
		run("mkdir", "results/figs")
	}



	info, err = os.Stat("bin")
	notDir = !(err == nil && info.IsDir()) 

	if notDir {
		run("mkdir", "bin")
	}
	


	resultPath := "results/benchmark.csv"

	if !fileExists(resultPath) {
		run("gcc" ,"-g","src/benchmark.c","-o","bin/benchmark","-lssl","-lcrypto","-lcjson")
		run("./bin/benchmark")
	}


	resultPath = "results/cache.json"

	if !fileExists(resultPath) {
		run("gcc" ,"-g","src/cache.c","-o","bin/cache","-lssl","-lcrypto","-lcjson")
		run("./bin/cache")
	}
}


func benchmarking() {


	binPath := "bin/ecdh"
	if !fileExists(binPath) {
		run("gcc" ,"-g","src/ecdh.c","-o","bin/ecdh","-lssl","-lcrypto","-lcjson")
	}


	binPath = "bin/mlkem"
	if !fileExists(binPath) {
		run("gcc" ,"-g","src/mlkem.c","-o","bin/mlkem","-lssl","-lcrypto","-lcjson")
	}

	binPath = "bin/runner"
	if !fileExists(binPath) {
		run("gcc" ,"-g","src/mlkem.c","-o","bin/mlkem","-lssl","-lcrypto","-lcjson")
	}


	run(binPath)

}


func dataAnalysis() {

}


func main() {

	setup()
	benchmarking()
}