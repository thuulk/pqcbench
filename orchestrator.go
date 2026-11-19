package main

import (
	//"errors"
	//"log"
	"os"
	"os/exec"
)


func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}


/** Setting up the benchmark dir and files if they are not set already */
func setup() {
	info, err := os.Stat("results")
	notDir := !(err == nil && info.IsDir()) 

	if notDir {
		exec.Command("mkdir", "results").Run()
		exec.Command("mkdir", "results/figs").Run()
	}



	info, err = os.Stat("bin")
	notDir = !(err == nil && info.IsDir()) 

	if notDir {
		exec.Command("mkdir", "bin").Run()
	}
	


	resultPath := "results/benchmark.csv"

	if !fileExists(resultPath) {
		exec.Command("gcc" ,"-g","src/benchmark.c","-o","bin/benchmark","-lssl","-lcrypto","-lcjson").Run()
		exec.Command("./bin/benchmark").Run()
	}


	resultPath = "results/cache.json"

	if !fileExists(resultPath) {
		exec.Command("gcc" ,"-g","src/cache.c","-o","bin/cache","-lssl","-lcrypto","-lcjson").Run()
		exec.Command("./bin/cache").Run()
	}
}


func benchmarking() {


	binPath := "bin/ecdh"
	if !fileExists(binPath) {
		exec.Command("gcc" ,"-g","src/ecdh.c","-o","bin/ecdh","-lssl","-lcrypto","-lcjson").Run()
	}


	binPath = "bin/mlkem"
	if !fileExists(binPath) {
		exec.Command("gcc" ,"-g","src/mlkem.c","-o","bin/mlkem","-lssl","-lcrypto","-lcjson").Run()
	}


	
	binPath = "./bin/ecdh"
	exec.Command(binPath).Run()

	binPath = "./bin/mlkem"
	exec.Command(binPath).Run()

}


func dataAnalysis() {

}


func main() {

	setup()
	benchmarking()

}