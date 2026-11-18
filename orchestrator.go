package main

import (
	//"errors"
	//"log"
	"os/exec"
	"os"
)


func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}


/** Setting up the benchmark dir and files if they are not set already*/
func setup() {
	info, err := os.Stat("results")
	notDir := !(err == nil && info.IsDir()) 

	if notDir {
		exec.Command("mkdir", "results").Run()
	}
	

	resultPath := "results/benchmark.csv"

	if !fileExists(resultPath) {
		exec.Command("gcc" ,"-g","src/benchmark.c","-o","bin/benchmark","-lssl","-lcrypto","-lcjson").Run()
		exec.Command("./bin/benchmark").Run()
	}

	if !fileExists("results/cache.json") {
		exec.Command("gcc" ,"-g","src/cache.c","-o","bin/cache","-lssl","-lcrypto","-lcjson").Run()
		exec.Command("./bin/cache").Run()
	}
}


func main() {

	setup()


	


}