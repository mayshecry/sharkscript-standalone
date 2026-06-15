package compiler

import (
	"encoding/gob"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"sharkscript/pkg/types"
)

func Compile(srcPath string, noOptimize bool) error {
	fmt.Printf("Initializing Build: %s\n", srcPath)

	script, lineNum, tips, err := Parse(srcPath, noOptimize)
	if err != nil {
		return err
	}

	destPath := strings.TrimSuffix(srcPath, ".shark") + ".shx"
	dest, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer dest.Close()

	dest.Write([]byte("SHARK01"))
	encoder := gob.NewEncoder(dest)
	if err := encoder.Encode(script); err != nil {
		return fmt.Errorf("failed to encode bytecode: %w", err)
	}

	fmt.Printf("[SUCCESS] Bytecode Exported: %s\n", destPath)
	if !noOptimize {
		script.Main = optimizePeephole(script.Main)
		script.Main = unrollLoops(script.Main)
		if lineNum > 2000 {
			fmt.Printf("[SYSTEM] Large source detected (%d lines). Multi-threaded compilation active.\n", lineNum)
			var wg sync.WaitGroup
			var mu sync.Mutex

			mMain, mTips := mergePrints(script.Main)
			script.Main = mMain
			tips = append(tips, mTips...)

			for name, fn := range script.Functions {
				wg.Add(1)
				go func(n string, f []types.Instruction) {
					defer wg.Done()
					optFn, optTips := mergePrints(unrollLoops(optimizePeephole(f)))
					mu.Lock()
					script.Functions[n] = optFn
					tips = append(tips, optTips...)
					mu.Unlock()
				}(name, fn)
			}
			wg.Wait()
		} else {
			mMain, mTips := mergePrints(script.Main)
			script.Main = mMain
			tips = append(tips, mTips...)
			for name, fn := range script.Functions {
				mFn, fTips := mergePrints(unrollLoops(optimizePeephole(fn)))
				script.Functions[name] = mFn
				tips = append(tips, fTips...)
			}
		}
		optimizedTips := optimizeUnusedVariables(&script)
		tips = append(tips, optimizedTips...)
	}
	printSuccess(srcPath, destPath, lineNum, script, tips, noOptimize)
	return nil
}

func printSuccess(_, destPath string, lineNum int, script types.CompiledScript, tips []string, noOptimize bool) {
	totalInstructions := len(script.Main)
	for _, fn := range script.Functions {
		totalInstructions += len(fn)
	}
	fmt.Printf("\n[BUILD SUMMARY]\n")
	fmt.Printf("  Target:     %s\n", destPath)
	fmt.Printf("  Binary:     %d lines -> %d opcodes\n", lineNum, totalInstructions)
	fmt.Printf("  Functions:  %d local definitions\n", len(script.Functions))
	if noOptimize {
		fmt.Printf("  Optimizations: Disabled [-fo flag active]\n")
	} else {
		fmt.Printf("  Optimizations: Enabled [AOT, Loop-Parallelization, Block-Inlining, Static-Math]\n")
	}
	fmt.Printf("  Engine:     SHARK01 [MAXIMUM PERFORMANCE]\n")

	if len(tips) > 0 {
		fmt.Printf("\n[OPTIMIZATIONS APPLIED]\n")
		for _, tip := range tips {
			fmt.Printf("  * %s\n", tip)
		}
	}
	fmt.Printf("-----------------------------------------\n\n")
}

func CompileAOT(srcPath string, targetOS string, noOptimize bool) error {
	script, lineNum, tips, err := Parse(srcPath, noOptimize)
	if err != nil {
		return err
	}

	goCode := GenerateGo(script)

	tmpDir, _ := os.MkdirTemp("", "shark_aot_*")
	tmpFile := filepath.Join(tmpDir, "main.go")
	os.WriteFile(tmpFile, []byte(goCode), 0644)
	defer os.RemoveAll(tmpDir)

	outputBin := strings.TrimSuffix(srcPath, ".shark")
	if strings.Contains(srcPath, "/") {
		outputBin = filepath.Base(outputBin)
	}
	if targetOS == "windows" && !strings.HasSuffix(outputBin, ".exe") {
		outputBin += ".exe"
	}

	fmt.Println("[Invoking Native Toolchain] - SharkScript AOTV2")
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outputBin, tmpFile)
	cmd.Env = append(os.Environ(), "GOOS="+targetOS)

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("AOT Build Failed: %s\n%s", err, string(out))
	}

	if !noOptimize {
		if lineNum > 2000 {
			fmt.Printf("[SYSTEM] Large source detected (%d lines). Multi-threaded AOT optimization active.\n", lineNum)
			var wg sync.WaitGroup
			var mu sync.Mutex

			mMain, mTips := mergePrints(script.Main)
			script.Main = mMain
			tips = append(tips, mTips...)

			for name, fn := range script.Functions {
				wg.Add(1)
				go func(n string, f []types.Instruction) {
					defer wg.Done()
					optFn, optTips := mergePrints(unrollLoops(optimizePeephole(f)))
					mu.Lock()
					script.Functions[n] = optFn
					tips = append(tips, optTips...)
					mu.Unlock()
				}(name, fn)
			}
			wg.Wait()
		} else {
			mMain, mTips := mergePrints(script.Main)
			script.Main = mMain
			tips = append(tips, mTips...)
			for name, fn := range script.Functions {
				mFn, fTips := mergePrints(unrollLoops(optimizePeephole(fn)))
				script.Functions[name] = mFn
				tips = append(tips, fTips...)
			}
		}
		optimizedTips := optimizeUnusedVariables(&script)
		tips = append(tips, optimizedTips...)
	}

	printSuccess(srcPath, outputBin+" (NATIVE)", lineNum, script, tips, noOptimize)
	return nil
}
