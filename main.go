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
	if len(os.Args) < 2 {
		fmt.Println("SharkScript CLI")
		fmt.Println("Usage:")
		fmt.Println("  shs <file.shark>          Compile to .shx")
		fmt.Println("  shs <file.shx>            Execute bytecode")
		fmt.Println("  shs compile <file.shark>")
		fmt.Println("  shs run <file.shx>")
		fmt.Println("  shs aot <file.shark> [-os <target_os>]")
		os.Exit(1)
	}

	var mode, file string
	var extraArgsStart int
	arg1 := strings.TrimPrefix(os.Args[1], "--")

	if strings.HasPrefix(os.Args[1], "--") {
		if len(os.Args) < 3 {
			fmt.Printf("Error: %s requires a file path\n", os.Args[1])
			os.Exit(1)
		}
		mode = os.Args[1]
		file = os.Args[2]
		extraArgsStart = 3
	} else if arg1 == "compile" || arg1 == "run" || arg1 == "aot" {
		mode = arg1
		file = os.Args[2]
		extraArgsStart = 3
	} else {
		file = os.Args[1]
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
		err := compiler.Compile(file)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Compiled %s successfully.\n", file)

	case "aot":
		targetOS := runtime.GOOS
		for i := 1; i < len(os.Args); i++ {
			if os.Args[i] == "-os" && i+1 < len(os.Args) {
				targetOS = os.Args[i+1]
			}
		}
		err := compiler.CompileAOT(file, targetOS)
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

		engine := vm.NewEngine(script, file)

		for i := extraArgsStart; i < len(os.Args); i++ {
			arg := os.Args[i]
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
		engine.Run(pkt)
		fmt.Println("Execution complete.")
	}
}
