package main

import (
	"encoding/gob"
	"fmt"
	"os"
	"strings"
	"time"

	"sharkscript/pkg/compiler"
	"sharkscript/pkg/types"
	"sharkscript/pkg/vm"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sharkscript --compile <file.shark>")
		fmt.Println("       sharkscript --run <file.ligma>")
		os.Exit(1)
	}

	mode := os.Args[1]
	file := os.Args[2]

	switch mode {
	case "--compile":
		err := compiler.Compile(file)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Compiled %s successfully.\n", file)

	case "--run":
		f, err := os.Open(file)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		header := make([]byte, 7)
		f.Read(header)
		if string(header) != "LIGMA02" {
			fmt.Println("Invalid bytecode format.")
			os.Exit(1)
		}

		var script types.CompiledScript
		if err := gob.NewDecoder(f).Decode(&script); err != nil {
			fmt.Printf("Failed to load script: %v\n", err)
			os.Exit(1)
		}

		engine := vm.NewEngine(script, file)

		for i := 3; i < len(os.Args); i++ {
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
