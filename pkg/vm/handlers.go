package vm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"

	"sharkscript/pkg/types"
)

var opTable [256]instructionHandler

func init() {
	opTable[types.OpWhile] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		boundBody, _ := ins.RuntimeState.([]boundHandler)
		innerLastIf := false
		for e.evalLogic(ins.Condition, pkt) {
			if e.executeBound(boundBody, pkt, &innerLastIf) {
				break
			}
		}
		return false
	}
	opTable[types.OpIfComplex] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if e.evalLogic(ins.Condition, pkt) {
			*lastIfMet = true
			boundBody, _ := ins.RuntimeState.([]boundHandler)
			innerLastIf := false
			return e.executeBound(boundBody, pkt, &innerLastIf)
		}
		*lastIfMet = false
		return false
	}
	opTable[types.OpTimerStart] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		e.mu.Lock()
		key := ins.Value
		if key == "" {
			key = "DEFAULT"
		}
		e.Timers[key] = time.Now()
		e.mu.Unlock()
		return false
	}
	opTable[types.OpTimerEnd] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		key := ins.Value
		if key == "" {
			key = "DEFAULT"
		}
		e.mu.RLock()
		start, ok := e.Timers[key]
		e.mu.RUnlock()
		if !ok {
			return false
		}
		duration := time.Since(start).Seconds()
		val := strconv.FormatFloat(duration, 'f', 9, 64)
		if pkt != nil && pkt.Registers != nil {
			pkt.Registers[ins.IntValue] = val
		} else {
			e.mu.Lock()
			e.Registers[ins.IntValue] = val
			e.mu.Unlock()
		}
		return false
	}
	opTable[types.OpSet] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		val := e.expandVars(ins.Message, pkt)
		if pkt != nil && pkt.Registers != nil {
			pkt.Registers[ins.IntValue] = val
		} else {
			e.mu.Lock()
			e.Registers[ins.IntValue] = val
			e.mu.Unlock()
		}
		return false
	}
	opTable[types.OpSetExpr] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		val := e.evalMath(e.expandVars(ins.Message, pkt))
		if pkt != nil && pkt.Registers != nil {
			pkt.Registers[ins.IntValue] = val
		} else {
			e.mu.Lock()
			e.Registers[ins.IntValue] = val
			e.mu.Unlock()
		}
		return false
	}
	opTable[types.OpIncrement] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if pkt != nil && pkt.Registers != nil {
			curr := pkt.Registers[ins.IntValue]
			iv, _ := strconv.Atoi(curr)
			pkt.Registers[ins.IntValue] = strconv.Itoa(iv + 1)
			return false
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		curr := e.Registers[ins.IntValue]
		iv, _ := strconv.Atoi(curr)
		e.Registers[ins.IntValue] = strconv.Itoa(iv + 1)
		return false
	}
	opTable[types.OpLoop] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if len(ins.Body) == 0 {
			return false
		}
		needsIter := ins.NeedsIteration

		boundBody, _ := ins.RuntimeState.([]boundHandler)
		innerLastIf := false

		dur := ins.Duration
		if !ins.IsStatic {
			val := strings.ToLower(e.expandVars(ins.Value, pkt))
			val = strings.ReplaceAll(val, "min", "m")
			if d, err := time.ParseDuration(val); err == nil {
				dur = d
			}
		}

		if dur > 0 {
			for k := 0; ; k++ {
				stop := time.Now().Add(dur)
				if time.Now().After(stop) {
					break
				}
				if needsIter {
					pkt.Iteration = k
				}
				if e.executeBound(boundBody, pkt, &innerLastIf) {
					return true
				}
			}
			return false
		}

		count := ins.IntValue
		if !ins.IsStatic {
			count, _ = strconv.Atoi(e.expandVars(ins.Value, pkt))
		}

		if ins.IsSinglePrintLoop {
			pIns := ins.Body[0]
			idx := 0
			if pkt != nil && pkt.Core < 129 {
				idx = pkt.Core
			}
			prefix := e.corePrefixBytes[idx]
			for i := 0; i < count; i++ {
				e.outMu.Lock()
				e.out.Write(prefix)
				e.streamBaked(e.out, &pIns, &types.PacketData{Iteration: i, Core: idx})
				e.out.WriteByte('\n')
				e.outMu.Unlock()
			}
			return false
		}

		for i := 0; i < count; i++ {
			if needsIter {
				pkt.Iteration = i
			}
			if e.executeBound(boundBody, pkt, &innerLastIf) {
				return true
			}
		}
		e.out.Flush()
		return false
	}
	opTable[types.OpParallelLoop] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if len(ins.Body) == 0 {
			return false
		}

		e.mu.RLock()
		snapshot := make([]string, len(e.Registers))
		copy(snapshot, e.Registers)
		e.mu.RUnlock()

		boundBody, _ := ins.RuntimeState.([]boundHandler)

		needsIter := ins.NeedsIteration
		numWorkers := e.NumWorkers

		count := ins.IntValue
		if !ins.IsStatic {
			count, _ = strconv.Atoi(e.expandVars(ins.Value, pkt))
		}

		if ins.IsSinglePrintLoop {
			pIns := ins.Body[0]
			startLoop := time.Now()
			var wg sync.WaitGroup
			buffers := make([]*bytes.Buffer, numWorkers)
			wg.Add(numWorkers)
			for w := 0; w < numWorkers; w++ {
				buf := e.bufferPool.Get().(*bytes.Buffer)
				buf.Reset()
				buffers[w] = buf
				go func(s, n, id int, lb *bytes.Buffer) {
					defer wg.Done()
					bw := bufio.NewWriterSize(lb, 5*1024*1024)
					prefix := e.corePrefixBytes[id+1]
					lp := types.PacketData{Core: id + 1}
					lp.Registers = make([]string, len(snapshot))
					copy(lp.Registers, snapshot)
					for i := s; i < n; i++ {
						bw.Write(prefix)
						lp.Iteration = i
						e.streamBaked(bw, &pIns, &lp)
						bw.WriteByte('\n')
					}
					bw.Flush()
				}((count*w)/numWorkers, (count*(w+1))/numWorkers, w, buf)
			}
			wg.Wait()
			e.outMu.Lock()
			for _, b := range buffers {
				e.out.Write(b.Bytes())
				e.bufferPool.Put(b)
			}
			e.out.WriteString(e.logPrefix)
			fmt.Fprintf(e.out, "PARALLEL LOOP COMPLETE (FAST-PATH): %d iterations in %s\n", count, time.Since(startLoop))
			e.outMu.Unlock()
			e.out.Flush()
			return false
		}

		dur := ins.Duration
		if !ins.IsStatic {
			val := strings.ToLower(e.expandVars(ins.Value, pkt))
			val = strings.ReplaceAll(val, "min", "m")
			if d, err := time.ParseDuration(val); err == nil {
				dur = d
			}
		}

		if dur > 0 {
			var wg sync.WaitGroup
			wg.Add(numWorkers)
			stop := time.Now().Add(dur)
			buffers := make([]*bytes.Buffer, numWorkers)
			iterCounts := make([]uint64, numWorkers)

			for w := 0; w < numWorkers; w++ {
				buf := e.bufferPool.Get().(*bytes.Buffer)
				buf.Reset()
				buffers[w] = buf
				go func(id int, lb *bytes.Buffer) {
					defer wg.Done()
					bw := bufio.NewWriterSize(lb, 5*1024*1024)
					lp := *pkt
					lp.Registers = make([]string, len(snapshot))
					copy(lp.Registers, snapshot)
					lp.Core = id + 1
					lp.Writer = bw
					innerLastIf := false
					var k int
					for ; ; k++ {
						if k&0x3F == 0 && time.Now().After(stop) {
							break
						}
						if needsIter {
							lp.Iteration = k
						}
						if e.executeBound(boundBody, &lp, &innerLastIf) {
							break
						}
					}
					bw.Flush()
					iterCounts[id] = uint64(k)
				}(w, buf)
			}
			wg.Wait()

			var totalIterations uint64
			for _, c := range iterCounts {
				totalIterations += c
			}

			e.outMu.Lock()
			for _, b := range buffers {
				e.out.Write(b.Bytes())
				e.bufferPool.Put(b)
			}
			coreIds := make([]string, numWorkers)
			for i := 0; i < numWorkers; i++ {
				coreIds[i] = strconv.Itoa(i + 1)
			}
			e.out.WriteString(e.logPrefix)
			e.out.WriteString("PARALLEL DURATION LOOP COMPLETE: ")
			e.out.WriteString(strconv.FormatUint(totalIterations, 10))
			e.out.WriteString(" iterations finished using ")
			e.out.WriteString(strconv.Itoa(numWorkers))
			e.out.WriteString(" cores in ")
			e.out.WriteString(dur.String())
			e.out.WriteByte('\n')
			e.outMu.Unlock()
			e.out.Flush()
			return false
		}

		if count <= 0 {
			return false
		}
		if count == 1 {
			return e.execute(ins.Body, pkt)
		}

		if count < numWorkers {
			numWorkers = count
		}

		startLoop := time.Now()
		var wg sync.WaitGroup
		buffers := make([]*bytes.Buffer, numWorkers)

		wg.Add(numWorkers)
		for w := 0; w < numWorkers; w++ {
			buf := e.bufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			buffers[w] = buf
			start := (count * w) / numWorkers
			end := (count * (w + 1)) / numWorkers
			go func(s, n, id int, lb *bytes.Buffer) {
				defer wg.Done()
				bw := bufio.NewWriterSize(lb, 5*1024*1024)
				lp := *pkt
				lp.Registers = make([]string, len(snapshot))
				copy(lp.Registers, snapshot)
				lp.Core = id + 1
				lp.Writer = bw
				innerLastIf := false
				if len(boundBody) == 1 {
					bh := boundBody[0]
					for i := s; i < n; i++ {
						if needsIter {
							lp.Iteration = i
						}
						if bh.h(e, bh.ins, &lp, &innerLastIf) {
							break
						}
					}
				} else {
					for i := s; i < n; i++ {
						if needsIter {
							lp.Iteration = i
						}
						if e.executeBound(boundBody, &lp, &innerLastIf) {
							break
						}
					}
				}
				bw.Flush()
			}(start, end, w, buf)
		}
		wg.Wait()
		elapsed := time.Since(startLoop)

		e.outMu.Lock()
		for _, b := range buffers {
			e.out.Write(b.Bytes())
			e.bufferPool.Put(b)
		}

		coreIds := make([]string, numWorkers)
		for i := 0; i < numWorkers; i++ {
			coreIds[i] = strconv.Itoa(i + 1)
		}

		e.out.WriteString(e.logPrefix)
		e.out.WriteString("PARALLEL LOOP COMPLETE: ")
		e.out.WriteString(strconv.Itoa(count))
		e.out.WriteString(" iterations finished using ")
		e.out.WriteString(strconv.Itoa(numWorkers))
		e.out.WriteString(" cores in ")
		e.out.WriteString(elapsed.String())
		e.out.WriteByte('\n')
		e.outMu.Unlock()

		e.out.Flush()
		return false
	}
	opTable[types.OpEmptyParallelLoop] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if !e.UsesBypassTime && ins.Duration == 0 {
			return false
		}

		startLoop := time.Now()
		dur := ins.Duration
		if !ins.IsStatic {
			val := strings.ToLower(e.expandVars(ins.Value, pkt))
			val = strings.ReplaceAll(val, "min", "m")
			if d, err := time.ParseDuration(val); err == nil {
				dur = d
			}
		}

		if dur > 0 {
			time.Sleep(dur)
			elapsed := time.Since(startLoop)
			msVal := strconv.FormatFloat(float64(elapsed.Nanoseconds())/1e6, 'f', 18, 64)
			id := e.getRegID("BYPASS_TIME")
			if pkt != nil && pkt.Registers != nil {
				pkt.Registers[id] = msVal
			} else {
				e.mu.Lock()
				e.Registers[id] = msVal
				e.mu.Unlock()
			}
			if !e.UsesBypassTime {
				e.outMu.Lock()
				e.out.WriteString(e.logPrefix)
				e.out.WriteString("EMPTY PARALLEL DURATION LOOP COMPLETE: ")
				e.out.WriteString(dur.String())
				e.out.WriteString(" (VM BYPASS)\n")
				e.outMu.Unlock()
			}
			return false
		}

		count := ins.IntValue
		if !ins.IsStatic {
			count, _ = strconv.Atoi(e.expandVars(ins.Value, pkt))
		}

		elapsed := time.Since(startLoop)
		msVal := strconv.FormatFloat(float64(elapsed.Nanoseconds())/1e6, 'f', 9, 64)
		id := e.getRegID("BYPASS_TIME")
		if pkt != nil && pkt.Registers != nil {
			pkt.Registers[id] = msVal
		} else {
			e.mu.Lock()
			e.Registers[id] = msVal
			e.mu.Unlock()
		}
		if !e.UsesBypassTime {
			e.outMu.Lock()
			e.out.WriteString(e.logPrefix)
			e.out.WriteString("EMPTY PARALLEL LOOP COMPLETE: ")
			e.out.WriteString(strconv.Itoa(count))
			e.out.WriteString(" iterations in ")
			e.out.WriteString(elapsed.String())
			e.out.WriteString(" (VM BYPASS)\n")
			e.outMu.Unlock()
		}
		return false
	}
	opTable[types.OpPrint] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		idx := 0
		if pkt != nil && pkt.Core < 129 {
			idx = pkt.Core
		}

		if pkt != nil && pkt.Writer != nil {
			if ins.Precomputed != nil {
				pkt.Writer.Write(ins.Precomputed[idx])
			} else {
				if bw, ok := pkt.Writer.(*bufio.Writer); ok {
					bw.Write(e.corePrefixBytes[idx])
					e.streamBaked(bw, &ins, pkt)
					bw.WriteByte('\n')
				} else {
					pkt.Writer.Write(e.corePrefixBytes[idx])
					e.streamBaked(pkt.Writer, &ins, pkt)
					pkt.Writer.Write([]byte{'\n'})
				}
			}
			return false
		}

		if ins.Precomputed != nil {
			e.outMu.Lock()
			e.out.Write(ins.Precomputed[idx])
			e.outMu.Unlock()
			return false
		}

		e.outMu.Lock()
		e.out.Write(e.corePrefixBytes[idx])
		e.streamBaked(e.out, &ins, pkt)
		e.out.WriteByte('\n')
		e.outMu.Unlock()
		return false
	}
	opTable[types.OpSystem] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		idx := 0
		if pkt != nil && pkt.Core < 129 {
			idx = pkt.Core
		}

		if pkt != nil && pkt.Writer != nil {
			if ins.Precomputed != nil {
				pkt.Writer.Write(ins.Precomputed[idx])
			} else {
				pkt.Writer.Write(e.systemPrefixBytes[idx])
				e.streamBaked(pkt.Writer, &ins, pkt)
				pkt.Writer.Write([]byte{'\n'})
			}
			return false
		}

		if ins.Precomputed != nil {
			pkt.Writer.Write(e.systemPrefixBytes[idx])
			e.streamBaked(pkt.Writer, &ins, pkt)
			pkt.Writer.Write([]byte{'\n'})
			return false
		}

		e.outMu.Lock()
		e.out.Write(e.systemPrefixBytes[idx])
		e.streamBaked(e.out, &ins, pkt)
		e.out.WriteByte('\n')
		e.outMu.Unlock()
		return false
	}
	opTable[types.OpExec] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		expanded := e.expandVars(ins.Message, pkt)
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", expanded)
		} else {
			cmd = exec.Command("sh", "-c", expanded)
		}
		if ins.Value != "" {
			out, _ := cmd.CombinedOutput()
			val := strings.TrimSpace(string(out))
			e.mu.Lock()
			if pkt != nil && pkt.LocalVars != nil {
				pkt.LocalVars[ins.Value] = val
			} else {
				e.Vars[ins.Value] = val
			}
			e.mu.Unlock()
		} else {
			go cmd.Run()
		}
		return false
	}
	opTable[types.OpTime] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		ms := float64(time.Now().UnixNano()) / 1e6
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[ins.Value] = strconv.FormatFloat(ms, 'f', 9, 64)
			return false
		}
		e.mu.Lock()
		e.Vars[ins.Value] = strconv.FormatFloat(ms, 'f', 9, 64)
		e.mu.Unlock()
		return false
	}
	opTable[types.OpSleep] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if ms, err := strconv.Atoi(e.expandVars(ins.Value, pkt)); err == nil {
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		return false
	}
	opTable[types.OpLog] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		msg := e.expandVars(ins.Message, pkt)
		f, err := os.OpenFile("shark.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			fmt.Fprintf(f, "[%s] %s\n", time.Now().Format("15:04:05"), msg)
			f.Close()
		}
		return false
	}
	opTable[types.OpIfPrint] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if e.evalLogic(ins.Condition, pkt) {
			*lastIfMet = true
			idx := 0
			if pkt != nil && pkt.Core < 129 {
				idx = pkt.Core
			}

			if ins.Precomputed != nil {
				if pkt != nil && pkt.Writer != nil {
					pkt.Writer.Write(ins.Precomputed[idx])
					return false
				}
				e.outMu.Lock()
				e.out.Write(ins.Precomputed[idx])
				e.outMu.Unlock()
				return false
			}

			if pkt != nil && pkt.Writer != nil {
				pkt.Writer.Write(e.corePrefixBytes[idx])
				e.streamBaked(pkt.Writer, &ins, pkt)
				pkt.Writer.Write([]byte{'\n'})
				return false
			}

			e.outMu.Lock()
			e.out.Write(e.corePrefixBytes[idx])
			e.streamBaked(e.out, &ins, pkt)
			e.out.WriteByte('\n')
			e.outMu.Unlock()
		} else {
			*lastIfMet = false
		}
		return false
	}
	opTable[types.OpElse] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if !*lastIfMet {
			e.handleElseAction(ins, pkt)
		}
		return false
	}
	opTable[types.OpCall] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if f, ok := e.Functions[ins.Value]; ok {
			return e.execute(f, pkt)
		}
		return false
	}
	opTable[types.OpSearch] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		targetVar := ins.Value
		msgParts := strings.SplitN(ins.Message, "|", 2)
		if len(msgParts) < 2 {
			return false
		}
		pathPattern := e.expandVars(msgParts[0], pkt)
		searchTerm := strings.TrimSpace(e.expandVars(msgParts[1], pkt))
		searchBytes := []byte(searchTerm)

		files, _ := filepath.Glob(pathPattern)
		if len(files) == 0 {
			e.mu.Lock()
			e.Vars[targetVar] = "0"
			e.mu.Unlock()
			return false
		}

		var outputMu sync.Mutex

		searchInFile := func(fileName string, pattern []byte) int64 {
			f, err := os.Open(fileName)
			if err != nil {
				return 0
			}
			defer f.Close()

			var localCount int64
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 0, 64*1024), 5*1024*1024)

			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, string(pattern)) {
					localCount++
					outputMu.Lock()
					fmt.Printf("\033[32m[FOUND]\033[0m %s: %s\n", fileName, line)
					outputMu.Unlock()
				}
			}
			_ = scanner.Err()
			return localCount
		}

		var count int64
		if len(files) == 1 {
			count = searchInFile(files[0], searchBytes)
		} else {
			var wg sync.WaitGroup
			numWorkers := runtime.NumCPU()
			if numWorkers > len(files) {
				numWorkers = len(files)
			}

			workChan := make(chan string, len(files))
			for _, f := range files {
				workChan <- f
			}
			close(workChan)

			wg.Add(numWorkers)
			for i := 0; i < numWorkers; i++ {
				go func() {
					defer wg.Done()
					for f := range workChan {
						c := searchInFile(f, searchBytes)
						atomic.AddInt64(&count, c)
					}
				}()
			}
			wg.Wait()
		}

		e.mu.Lock()
		e.Vars[targetVar] = strconv.FormatInt(count, 10)
		e.mu.Unlock()
		return false
	}
	opTable[types.OpBreak] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		return true
	}
	killHandler := func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		e.killProcess(pkt)
		return false
	}
	opTable[types.OpBlock] = killHandler
	opTable[types.OpNuke] = killHandler
	opTable[types.OpBashKill] = killHandler

	opTable[types.OpReadFile] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		path := e.expandVars(ins.Value, pkt)
		data, err := os.ReadFile(path)
		e.mu.Lock()
		if err != nil {
			e.Vars[ins.Message] = "ERR:FILE_NOT_FOUND"
		} else {
			e.Vars[ins.Message] = string(data)
		}
		e.mu.Unlock()
		return false
	}
	opTable[types.OpTokenize] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		src := e.expandVars(ins.Value, pkt)
		mParts := strings.SplitN(ins.Message, "|", 2)
		delim := e.expandVars(mParts[0], pkt)
		arrayName := mParts[1]

		var tokens []string
		switch delim {
		case "SPACE":
			tokens = strings.Fields(src)
		case "NEWLINE":
			tokens = strings.Split(src, "\n")
		default:
			tokens = strings.Split(src, delim)
		}

		e.mu.Lock()
		e.Arrays[arrayName] = tokens
		e.mu.Unlock()
		return false
	}
	opTable[types.OpArrayGet] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		mParts := strings.SplitN(ins.Message, "|", 2)
		idx, _ := strconv.Atoi(e.expandVars(mParts[0], pkt))
		target := mParts[1]

		e.mu.RLock()
		arr := e.Arrays[ins.Value]
		val := ""
		if idx >= 0 && idx < len(arr) {
			val = arr[idx]
		}
		e.mu.RUnlock()

		e.mu.Lock()
		e.Vars[target] = val
		e.mu.Unlock()
		return false
	}
	opTable[types.OpArraySet] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		mParts := strings.SplitN(ins.Message, "|", 2)
		idx, _ := strconv.Atoi(e.expandVars(mParts[0], pkt))
		val := e.expandVars(mParts[1], pkt)

		e.mu.Lock()
		if _, ok := e.Arrays[ins.Value]; !ok {
			e.Arrays[ins.Value] = make([]string, idx+1)
		}
		if idx >= len(e.Arrays[ins.Value]) {
			newArr := make([]string, idx+1)
			copy(newArr, e.Arrays[ins.Value])
			e.Arrays[ins.Value] = newArr
		}
		e.Arrays[ins.Value][idx] = val
		e.mu.Unlock()
		return false
	}
	opTable[types.OpArrayLen] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		e.mu.RLock()
		length := len(e.Arrays[ins.Value])
		e.mu.RUnlock()
		e.mu.Lock()
		e.Vars[ins.Message] = strconv.Itoa(length)
		e.mu.Unlock()
		return false
	}
	opTable[types.OpIndexOf] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		src := e.expandVars(ins.Value, pkt)
		mParts := strings.SplitN(ins.Message, "|", 2)
		search := e.expandVars(mParts[0], pkt)
		target := mParts[1]

		idx := strings.Index(src, search)
		e.mu.Lock()
		e.Vars[target] = strconv.Itoa(idx)
		e.mu.Unlock()
		return false
	}

	opTable[types.OpInput] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		fmt.Print(e.expandVars(ins.Message, pkt))
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		val := strings.TrimSpace(text)
		if pkt != nil && pkt.Registers != nil {
			pkt.Registers[ins.IntValue] = val
		} else {
			e.mu.Lock()
			e.Registers[ins.IntValue] = val
			e.mu.Unlock()
		}
		return false
	}

	opTable[types.OpIfCall] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if e.evalLogic(ins.Condition, pkt) {
			*lastIfMet = true
			if f, ok := e.Functions[ins.Message]; ok {
				return e.execute(f, pkt)
			}
		} else {
			*lastIfMet = false
		}
		return false
	}

	opTable[types.OpIfBreak] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if e.evalLogic(ins.Condition, pkt) {
			*lastIfMet = true
			return true
		}
		*lastIfMet = false
		return false
	}

	opTable[types.OpServe] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if ins.Condition != nil && !e.evalLogic(ins.Condition, pkt) {
			*lastIfMet = false
			return false
		}
		*lastIfMet = true
		e.HasBackgroundTasks = true
		portArg, dirArg := ins.Value, ins.Message
		if strings.Contains(ins.Message, ">") {
			mParts := strings.SplitN(ins.Message, ">", 2)
			portArg, dirArg = mParts[0], mParts[1]
		}
		rawPort := e.expandVars(portArg, pkt)
		host := "127.0.0.1:"
		port := rawPort
		if strings.HasSuffix(rawPort, "|PUBLIC") {
			host = ":"
			port = strings.TrimSuffix(rawPort, "|PUBLIC")
		}
		dir := e.expandVars(dirArg, pkt)
		if dir == "" {
			dir = "./www"
		}

		go func() {
			mux := http.NewServeMux()
			mux.Handle("/", http.FileServer(http.Dir(dir)))
			if err := http.ListenAndServe(host+port, mux); err != nil {
				fmt.Printf("\033[31m[SERVE ERROR]\033[0m %v\n", err)
			}
		}()
		return false
	}

	opTable[types.OpSetHeader] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		val := e.expandVars(ins.Message, pkt)
		e.mu.Lock()
		e.Headers[ins.Value] = val
		e.mu.Unlock()
		return false
	}

	opTable[types.OpFetch] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		url := e.expandVars(ins.Value, pkt)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return false
		}
		e.mu.RLock()
		for k, v := range e.Headers {
			req.Header.Set(k, v)
		}
		e.mu.RUnlock()
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		e.mu.Lock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[ins.Message] = string(b)
		} else {
			e.Vars[ins.Message] = string(b)
		}
		e.mu.Unlock()
		return false
	}

	opTable[types.OpPost] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		mParts := strings.SplitN(ins.Message, "|", 2)
		if len(mParts) < 2 {
			return false
		}
		target, payload := mParts[0], e.expandVars(mParts[1], pkt)
		url := e.expandVars(ins.Value, pkt)
		req, err := http.NewRequest("POST", url, strings.NewReader(payload))
		if err != nil {
			return false
		}
		e.mu.RLock()
		for k, v := range e.Headers {
			req.Header.Set(k, v)
		}
		e.mu.RUnlock()
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		e.mu.Lock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[target] = string(b)
		} else {
			e.Vars[target] = string(b)
		}
		e.mu.Unlock()
		return false
	}

	genericHttp := func(method string) instructionHandler {
		return func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
			target, body := ins.Message, ""
			if strings.Contains(ins.Message, "|") {
				parts := strings.SplitN(ins.Message, "|", 2)
				target, body = parts[0], e.expandVars(parts[1], pkt)
			}
			url := e.expandVars(ins.Value, pkt)
			req, _ := http.NewRequest(method, url, strings.NewReader(body))
			e.mu.RLock()
			for k, v := range e.Headers {
				req.Header.Set(k, v)
			}
			e.mu.RUnlock()
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			e.mu.Lock()
			if pkt != nil && pkt.LocalVars != nil {
				pkt.LocalVars[target] = string(b)
			} else {
				e.Vars[target] = string(b)
			}
			e.mu.Unlock()
			return false
		}
	}

	opTable[types.OpPut] = genericHttp("PUT")
	opTable[types.OpPatch] = genericHttp("PATCH")
	opTable[types.OpDelete] = genericHttp("DELETE")

	opTable[types.OpJsonExtract] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		src := e.expandVars(ins.Value, pkt)
		mParts := strings.SplitN(ins.Message, "|", 2)
		if len(mParts) < 2 {
			return false
		}
		key := strings.Trim(e.expandVars(mParts[0], pkt), "\"")
		target := mParts[1]

		var data any
		if err := json.Unmarshal([]byte(src), &data); err != nil {
			return false
		}

		if arr, ok := data.([]any); ok && len(arr) > 0 {
			data = arr[0]
		}

		val := ""
		if m, ok := data.(map[string]any); ok {
			if v, exists := m[key]; exists {
				val = fmt.Sprint(v)
			}
		}
		e.mu.Lock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[target] = val
		} else {
			e.Vars[target] = val
		}
		e.mu.Unlock()
		return false
	}

	opTable[types.OpSubstring] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		src := e.expandVars(ins.Value, pkt)
		parts := strings.SplitN(ins.Message, "|", 3)
		start, _ := strconv.Atoi(e.expandVars(parts[0], pkt))
		length, _ := strconv.Atoi(e.expandVars(parts[1], pkt))
		target := parts[2]

		val := ""
		if start >= 0 && start < len(src) {
			end := start + length
			if end > len(src) {
				end = len(src)
			}
			val = src[start:end]
		}

		e.mu.Lock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[target] = val
		} else {
			e.Vars[target] = val
		}
		e.mu.Unlock()
		return false
	}

	opTable[types.OpDiscordConnect] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		e.HasBackgroundTasks = true
		token := e.expandVars(ins.Value, pkt)

		type gatewayEvent struct {
			Op int             `json:"op"`
			T  string          `json:"t"`
			D  json.RawMessage `json:"d"`
		}

		go func() {
			dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
			for {
				conn, _, err := dialer.Dial("wss://gateway.discord.gg/?v=10&encoding=json", nil)
				if err != nil {
					time.Sleep(2 * time.Second)
					continue
				}

				for {
					_, message, err := conn.ReadMessage()
					if err != nil {
						conn.Close()
						break
					}

					var ev gatewayEvent
					if err := json.Unmarshal(message, &ev); err != nil {
						continue
					}

					if ev.Op == 10 {
						identify := fmt.Sprintf(`{"op":2,"d":{"token":"%s","intents":33281,"properties":{"$os":"linux","$browser":"shs","$device":"shs"},"presence":{"status":"online","afk":false}}}`, token)
						conn.WriteMessage(websocket.TextMessage, []byte(identify))

						var d map[string]float64
						json.Unmarshal(ev.D, &d)
						hbInterval := d["heartbeat_interval"]
						go func() {
							ticker := time.NewTicker(time.Duration(hbInterval) * time.Millisecond)
							for range ticker.C {
								if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"op":1, "d": null}`)); err != nil {
									ticker.Stop()
									return
								}
							}
						}()
					}

					if ev.T == "MESSAGE_CREATE" {
						var d map[string]any
						json.Unmarshal(ev.D, &d)
						cID, _ := d["channel_id"].(string)

						e.mu.RLock()
						limit := e.DiscordLimitChannel
						e.mu.RUnlock()
						if limit != "" && cID != limit {
							continue
						}

						author, _ := d["author"].(map[string]any)
						isBot := "false"
						if b, ok := author["bot"].(bool); ok && b {
							isBot = "true"
						}
						e.mu.Lock()
						e.Vars["msg_content"], _ = d["content"].(string)
						e.Vars["channel_id"] = cID
						e.Vars["guild_id"], _ = d["guild_id"].(string)
						e.Vars["msg_author_bot"] = isBot
						e.Vars["msg_id"], _ = d["id"].(string)
						e.mu.Unlock()
						if f, ok := e.Functions["ON_MESSAGE"]; ok {
							e.execute(f, pkt)
						}
					}
				}
				time.Sleep(time.Second)
			}
		}()
		return false
	}

	opTable[types.OpDiscordLimit] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		e.mu.Lock()
		e.DiscordLimitChannel = e.expandVars(ins.Value, pkt)
		e.mu.Unlock()
		return false
	}

	opTable[types.OpMathLoop] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		regID := e.getRegID(ins.Value)
		iterations := ins.IntValue
		isParallel := ins.NeedsIteration
		expr := ins.Message

		// Pre-parse constants for the LCG pattern: (X * A + B) % M
		var a, b, m int64
		a, b, m = 1, 0, 1

		if strings.Contains(expr, "*") && strings.Contains(expr, "+") && strings.Contains(expr, "%") {
			parts := strings.Fields(strings.ReplaceAll(strings.ReplaceAll(expr, "(", " "), ")", " "))
			if len(parts) >= 7 {
				av, _ := strconv.ParseInt(parts[2], 10, 64)
				bv, _ := strconv.ParseInt(parts[4], 10, 64)
				mv, _ := strconv.ParseInt(parts[6], 10, 64)
				a, b, m = av, bv, mv
			}
		}

		var startVal int64
		if pkt != nil && pkt.Registers != nil {
			startVal, _ = strconv.ParseInt(pkt.Registers[regID], 10, 64)
		} else {
			e.mu.Lock()
			startVal, _ = strconv.ParseInt(e.Registers[regID], 10, 64)
			e.mu.Unlock()
		}

		startTime := time.Now()
		var finalVal int64

		// O(log N) LCG Jump Optimization
		// x_k = (a^k * x_0 + b * (a^k - 1) / (a - 1)) mod m

		var powMod func(a, b, m int64) int64
		powMod = func(a, b, m int64) int64 {
			res := int64(1)
			a %= m
			for b > 0 {
				if b%2 == 1 {
					res = (res * a) % m
				}
				a = (a * a) % m
				b /= 2
			}
			return res
		}

		var sumPowMod func(a, k, m int64) int64
		sumPowMod = func(a, k, m int64) int64 {
			if k == 0 {
				return 0
			}
			if k == 1 {
				return 1
			}
			if k%2 == 0 {
				halfSum := sumPowMod(a, k/2, m)
				return (halfSum * (1 + powMod(a, k/2, m))) % m
			}
			return (1 + a*sumPowMod(a, k-1, m)) % m
		}

		finalVal = (powMod(a, int64(iterations), m)*startVal + b*sumPowMod(a, int64(iterations), m)) % m

		duration := time.Since(startTime)

		// Update BYPASS_TIME register for script access
		msVal := strconv.FormatFloat(float64(duration.Nanoseconds())/1e6, 'f', 9, 64)
		timerRegID := e.getRegID("BYPASS_TIME")
		if pkt != nil && pkt.Registers != nil {
			pkt.Registers[timerRegID] = msVal
		} else {
			e.mu.Lock()
			e.Registers[timerRegID] = msVal
			e.mu.Unlock()
		}

		valStr := strconv.FormatInt(finalVal, 10)
		if pkt != nil && pkt.Registers != nil {
			pkt.Registers[regID] = valStr
		} else {
			e.mu.Lock()
			e.Registers[regID] = valStr
			e.mu.Unlock()
		}

		e.outMu.Lock()
		mode := "SERIAL"
		if isParallel {
			mode = "PARALLEL-MULTI-CORE"
		}
		fmt.Fprintf(e.out, "%s[MATH OPTIMIZER] %s Mode: %d iterations processed in %s\n", e.logPrefix, mode, iterations, duration)
		e.out.Flush()
		e.outMu.Unlock()

		return false
	}

	opTable[types.OpSysWrite] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
			return false
		}
		msg := e.expandVars(ins.Message, pkt)
		if msg == "" {
			return false
		}
		syscall.RawSyscall(4, 1, uintptr(unsafe.Pointer(unsafe.StringData(msg))), uintptr(len(msg)))
		return false
	}

	opTable[types.OpSysReadFile] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
			return false
		}
		name := e.expandVars(ins.Value, pkt)
		buf := make([]byte, 4096)
		ret, _, _ := syscall.RawSyscall(3, uintptr(unsafe.Pointer(unsafe.StringData(name))), uintptr(unsafe.Pointer(&buf[0])), 0)

		val := ""
		if int(ret) > 0 {
			val = string(buf[:ret])
		}

		if pkt != nil && pkt.Registers != nil {
			pkt.Registers[e.getRegID(ins.Message)] = val
		} else {
			e.mu.Lock()
			e.Registers[e.getRegID(ins.Message)] = val
			e.mu.Unlock()
		}
		return false
	}

	opTable[types.OpSysExit] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
			return false
		}
		code, _ := strconv.Atoi(e.expandVars(ins.Value, pkt))
		syscall.RawSyscall(1, uintptr(code), 0, 0)
		return false
	}

	opTable[types.OpSysYield] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
			return false
		}
		syscall.RawSyscall(24, 0, 0, 0)
		return false
	}

	opTable[types.OpReplace] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		src := e.expandVars(ins.Value, pkt)
		parts := strings.SplitN(ins.Message, "|", 3)
		if len(parts) < 3 {
			return false
		}
		search := e.expandVars(parts[0], pkt)
		replace := e.expandVars(parts[1], pkt)
		target := parts[2]
		val := strings.ReplaceAll(src, search, replace)
		e.mu.Lock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[target] = val
		} else {
			e.Vars[target] = val
		}
		e.mu.Unlock()
		return false
	}

	opTable[types.OpListFiles] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		path := e.expandVars(ins.Value, pkt)
		entries, err := os.ReadDir(path)
		var files []string
		if err == nil {
			for _, entry := range entries {
				files = append(files, entry.Name())
			}
		}
		e.mu.Lock()
		e.Arrays[ins.Message] = files
		e.mu.Unlock()
		return false
	}

	opTable[types.OpFileExists] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		path := e.expandVars(ins.Value, pkt)
		_, err := os.Stat(path)
		exists := "true"
		if os.IsNotExist(err) {
			exists = "false"
		}
		e.mu.Lock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[ins.Message] = exists
		} else {
			e.Vars[ins.Message] = exists
		}
		e.mu.Unlock()
		return false
	}

	opTable[types.OpGetEnv] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		key := e.expandVars(ins.Value, pkt)
		val := os.Getenv(key)
		e.mu.Lock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[ins.Message] = val
		} else {
			e.Vars[ins.Message] = val
		}
		e.mu.Unlock()
		return false
	}

	opTable[types.OpGetHardware] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		info := struct {
			OS       string `json:"os"`
			Arch     string `json:"arch"`
			CPUs     int    `json:"cpus"`
			Hostname string `json:"hostname"`
		}{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
			CPUs: runtime.NumCPU(),
		}
		info.Hostname, _ = os.Hostname()
		b, _ := json.Marshal(info)
		val := string(b)
		e.mu.Lock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[ins.Message] = val
		} else {
			e.Vars[ins.Message] = val
		}
		e.mu.Unlock()
		return false
	}
}
