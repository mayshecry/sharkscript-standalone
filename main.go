package main

import (
	"encoding/gob"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"sharkscript/pkg/compiler"
	"sharkscript/pkg/types"
	"sharkscript/pkg/vm"
)

func main() {
	noOptimize := false
	args := make([]string, 0, len(os.Args))
	for _, arg := range os.Args {
		if arg == "-fo" {
			noOptimize = true
			continue
		}
		args = append(args, arg)
	}

	if len(args) < 2 {
		fmt.Println("SharkScript CLI")
		fmt.Println("Usage:")
		fmt.Println("  shs <file.shark>             Compile to .shx")
		fmt.Println("  shs <file.shx>               Execute bytecode")
		fmt.Println("  shs compile <file.shark>     Compile source")
		fmt.Println("  shs run <file.shx>           Run VM")
		fmt.Println("  shs aot <file.shark> [-os]   Native build")
		fmt.Println("  -fo                          Disable auto-optimization")
		os.Exit(1)
	}

	var mode, file string
	var extraArgsStart int
	arg1 := strings.TrimPrefix(args[1], "--")

	if strings.HasPrefix(args[1], "--") {
		if len(args) < 3 {
			fmt.Printf("Error: %s requires a file path\n", args[1])
			os.Exit(1)
		}
		mode = args[1]
		file = args[2]
		extraArgsStart = 3
	} else if arg1 == "compile" || arg1 == "run" || arg1 == "aot" {
		mode = arg1
		file = args[2]
		extraArgsStart = 3
	} else {
		file = args[1]
		extraArgsStart = 2
		if strings.HasSuffix(file, ".shark") {
			mode = "compile"
		} else {
			mode = "run"
		}
	}
	mode = strings.TrimPrefix(mode, "--")

	switch mode {
	case "compile":
		err := compiler.Compile(file, noOptimize)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Compiled %s successfully.\n", file)

	case "aot":
		targetOS := runtime.GOOS
		for i := 1; i < len(args); i++ {
			if args[i] == "-os" && i+1 < len(args) {
				targetOS = args[i+1]
			}
		}
		err := compiler.CompileAOT(file, targetOS, noOptimize)
		if err != nil {
			fmt.Printf("AOT Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("AOT Build complete.\n")

	case "run":
		f, err := os.Open(file)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		header := make([]byte, 7)
		f.Read(header)
		if string(header) != "SHARK01" {
			fmt.Println("Invalid bytecode format.")
			os.Exit(1)
		}

		var script types.CompiledScript
		if err := gob.NewDecoder(f).Decode(&script); err != nil {
			fmt.Printf("Failed to load script: %v\n", err)
			os.Exit(1)
		}

		engine := vm.NewEngine(script, file, noOptimize)

		for i := extraArgsStart; i < len(args); i++ {
			arg := args[i]
			if strings.HasPrefix(arg, "--") && strings.Contains(arg, "=") {
				kv := strings.SplitN(arg[2:], "=", 2)
				engine.Vars[kv[0]] = kv[1]
			}
		}

		pkt := &types.PacketData{
			Timestamp:   time.Now(),
			SrcIP:       "127.0.0.1",
			DstIP:       "8.8.8.8",
			Protocol:    "TCP",
			ProcessName: "Standalone-Test",
			Payload:     []byte("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"),
		}

		fmt.Printf("Executing %s...\n", file)
		globalStart := time.Now()
		engine.Run(pkt)
		fmt.Printf("Execution complete (Total Wall-Clock Time: %s).\n", time.Since(globalStart))
	}
}
