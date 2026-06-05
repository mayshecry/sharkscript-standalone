package vm

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sharkscript/pkg/types"
)

type Engine struct {
	Filename          string
	Instructions      []types.Instruction
	Functions         map[string][]types.Instruction
	Imports           map[string]bool
	Vars              map[string]string
	Arrays            map[string][]string
	Headers           map[string]string
	Timers            map[string]time.Time
	mu                sync.RWMutex
	out               *bufio.Writer
	NumWorkers        int
	outMu             sync.Mutex
	UsesBypassTime    bool
	bufferPool        sync.Pool
	logPrefix         string
	templateCache     sync.Map
	corePrefixes      []string
	corePrefixBytes   [][]byte
	systemPrefixes    []string
	systemPrefixBytes [][]byte
}

type boundHandler struct {
	h   instructionHandler
	ins types.Instruction
}

func NewEngine(script types.CompiledScript, filename string) *Engine {
	e := &Engine{
		Filename:       filename,
		Instructions:   script.Main,
		Functions:      script.Functions,
		Imports:        make(map[string]bool),
		Vars:           make(map[string]string),
		Arrays:         make(map[string][]string),
		Headers:        make(map[string]string),
		Timers:         make(map[string]time.Time),
		out:            bufio.NewWriterSize(os.Stdout, 128*1024),
		NumWorkers:     runtime.GOMAXPROCS(0),
		UsesBypassTime: script.UsesBypassTime,
		bufferPool: sync.Pool{
			New: func() any { return bytes.NewBuffer(make([]byte, 0, 1024*1024)) },
		},
		logPrefix: "[" + filename + "] ",
	}
	for _, imp := range script.Imports {
		e.Imports[imp] = true
	}

	e.corePrefixes = make([]string, 129)
	e.corePrefixBytes = make([][]byte, 129)
	e.systemPrefixes = make([]string, 129)
	e.systemPrefixBytes = make([][]byte, 129)
	for i := 0; i < 129; i++ {
		p := "[" + filename + "] "
		if i > 0 {
			p = fmt.Sprintf("[%s] [Core %d] ", filename, i)
		}
		e.corePrefixes[i] = p
		e.corePrefixBytes[i] = []byte(p)
		sys := p + "[SYSTEM] "
		e.systemPrefixes[i] = sys
		e.systemPrefixBytes[i] = []byte(sys)
	}

	e.bake(e.Instructions)
	for _, fn := range e.Functions {
		e.bake(fn)
	}

	return e
}

func (e *Engine) bake(insts []types.Instruction) {
	for i := range insts {
		ins := &insts[i]

		if !ins.IsStatic {
			if strings.Contains(ins.Message, "%") {
				ins.TemplateParts = e.parseTemplate(ins.Message)
			}
			if strings.Contains(ins.Value, "%") {
			}
		}

		if ins.IsStatic {
			switch ins.Op {
			case types.OpPrint, types.OpIfPrint:
				ins.Precomputed = make([][]byte, 129)
				for c := 0; c < 129; c++ {
					line := make([]byte, len(e.corePrefixBytes[c])+len(ins.Message)+1)
					copy(line, e.corePrefixBytes[c])
					copy(line[len(e.corePrefixBytes[c]):], ins.Message)
					line[len(line)-1] = '\n'
					ins.Precomputed[c] = line
				}
			case types.OpSystem:
				ins.Precomputed = make([][]byte, 129)
				for c := 0; c < 129; c++ {
					line := make([]byte, len(e.systemPrefixBytes[c])+len(ins.Message)+1)
					copy(line, e.systemPrefixBytes[c])
					copy(line[len(e.systemPrefixBytes[c]):], ins.Message)
					line[len(line)-1] = '\n'
					ins.Precomputed[c] = line
				}
			case types.OpSetExpr:
				ins.Message = e.evalMath(ins.Message)
				ins.Op = types.OpSet
			}
		}
		if len(ins.Body) > 0 {
			e.bake(ins.Body)
			if ins.Op == types.OpWhile || ins.Op == types.OpLoop || ins.Op == types.OpParallelLoop {
				bound := make([]boundHandler, len(ins.Body))
				for j, bIns := range ins.Body {
					bound[j] = boundHandler{h: opTable[bIns.Op], ins: bIns}
				}
				ins.RuntimeState = bound
			}
		}
	}
}

func (e *Engine) Run(pkt *types.PacketData) {
	e.execute(e.Instructions, pkt)
	e.out.Flush()
}

type instructionHandler func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool

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
		e.mu.Lock()
		defer e.mu.Unlock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[ins.Value] = strconv.FormatFloat(duration, 'f', 9, 64)
			return false
		}
		e.Vars[ins.Value] = strconv.FormatFloat(duration, 'f', 9, 64)
		return false
	}
	opTable[types.OpSet] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		var val string
		if ins.IsStatic {
			val = ins.Message
		} else {
			val = e.expandVars(ins.Message, pkt)
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[ins.Value] = val
			return false
		}
		e.Vars[ins.Value] = val
		return false
	}
	opTable[types.OpSetExpr] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		val := e.evalMath(e.expandVars(ins.Message, pkt))
		e.mu.Lock()
		defer e.mu.Unlock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[ins.Value] = val
			return false
		}
		e.Vars[ins.Value] = val
		return false
	}
	opTable[types.OpIncrement] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if pkt != nil && pkt.LocalVars != nil {
			curr := pkt.LocalVars[ins.Value]
			iv, _ := strconv.Atoi(curr)
			pkt.LocalVars[ins.Value] = strconv.Itoa(iv + 1)
			return false
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		curr := e.Vars[ins.Value]
		iv, _ := strconv.Atoi(curr)
		e.Vars[ins.Value] = strconv.Itoa(iv + 1)
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
				e.writeExpanded(e.out, &pIns, &types.PacketData{Iteration: i, Core: idx})
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
		snapshot := make(map[string]string, len(e.Vars))
		for k, v := range e.Vars {
			snapshot[k] = v
		}
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
					bw := bufio.NewWriterSize(lb, 1024*1024)
					prefix := e.corePrefixBytes[id+1]
					lp := types.PacketData{Core: id + 1}
					for i := s; i < n; i++ {
						bw.Write(prefix)
						lp.Iteration = i
						e.writeExpanded(bw, &pIns, &lp)
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
					bw := bufio.NewWriterSize(lb, 1024*1024)
					lp := *pkt
					localVars := make(map[string]string, len(snapshot))
					for k, v := range snapshot {
						localVars[k] = v
					}
					lp.LocalVars = localVars
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
				bw := bufio.NewWriterSize(lb, 1024*1024)
				lp := *pkt
				localVars := make(map[string]string, len(snapshot))
				for k, v := range snapshot {
					localVars[k] = v
				}
				lp.LocalVars = localVars
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
			msVal := strconv.FormatFloat(float64(elapsed.Nanoseconds())/1e6, 'f', 9, 64)
			e.mu.Lock()
			e.Vars["BYPASS_TIME"] = msVal
			if pkt != nil && pkt.LocalVars != nil {
				pkt.LocalVars["BYPASS_TIME"] = msVal
			}
			e.mu.Unlock()
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
		e.mu.Lock()
		e.Vars["BYPASS_TIME"] = msVal
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars["BYPASS_TIME"] = msVal
		}
		e.mu.Unlock()
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
					e.writeExpanded(bw, &ins, pkt)
					bw.WriteByte('\n')
				} else {
					pkt.Writer.Write(e.corePrefixBytes[idx])
					e.writeExpanded(pkt.Writer, &ins, pkt)
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
		e.writeExpanded(e.out, &ins, pkt)
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
				e.writeExpanded(pkt.Writer, &ins, pkt)
				pkt.Writer.Write([]byte{'\n'})
			}
			return false
		}

		if ins.Precomputed != nil {
			pkt.Writer.Write(e.systemPrefixBytes[idx])
			e.writeExpanded(pkt.Writer, &ins, pkt)
			pkt.Writer.Write([]byte{'\n'})
			return false
		}

		e.outMu.Lock()
		e.out.Write(e.systemPrefixBytes[idx])
		e.writeExpanded(e.out, &ins, pkt)
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
				e.writeExpanded(pkt.Writer, &ins, pkt)
				pkt.Writer.Write([]byte{'\n'})
				return false
			}

			e.outMu.Lock()
			e.out.Write(e.corePrefixBytes[idx])
			e.writeExpanded(e.out, &ins, pkt)
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
			scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

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
		e.mu.Lock()
		defer e.mu.Unlock()
		if pkt != nil && pkt.LocalVars != nil {
			pkt.LocalVars[ins.Value] = val
		} else {
			e.Vars[ins.Value] = val
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
}

func (e *Engine) execute(insts []types.Instruction, pkt *types.PacketData) bool {
	if len(insts) == 0 {
		return false
	}

	lastIfMet := false
	for _, ins := range insts {
		if handler := opTable[ins.Op]; handler != nil {
			if handler(e, ins, pkt, &lastIfMet) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) handleElseAction(ins types.Instruction, pkt *types.PacketData) bool {
	msg := e.expandVars(ins.Message, pkt)
	switch ins.Value {
	case "ELSE_PRINT":
		idx := 0
		if pkt != nil && pkt.Core > 0 && pkt.Core < 129 {
			idx = pkt.Core
		}

		if pkt != nil && pkt.Writer != nil {
			pkt.Writer.Write([]byte(e.corePrefixes[idx]))
			pkt.Writer.Write([]byte(msg))
			pkt.Writer.Write([]byte{'\n'})
			return false
		}

		e.outMu.Lock()
		e.out.WriteString(e.corePrefixes[idx])
		e.out.WriteString(msg)
		e.out.WriteByte('\n')
		e.outMu.Unlock()
	case "ELSE_CALL":
		if f, ok := e.Functions[msg]; ok {
			return e.execute(f, pkt)
		}
	case "ELSE_BLOCK":
		e.killProcess(pkt)
	}
	return false
}

func (e *Engine) containsIter(insts []types.Instruction) bool {
	for _, ins := range insts {
		if strings.Contains(ins.Message, "%ITER%") || strings.Contains(ins.Value, "%ITER%") {
			return true
		}
		if len(ins.Body) > 0 && e.containsIter(ins.Body) {
			return true
		}
	}
	return false
}

func (e *Engine) evalLogic(expr *types.LogicExpr, pkt *types.PacketData) bool {
	if expr == nil {
		return false
	}
	switch expr.Op {
	case types.LogOr:
		return e.evalLogic(expr.Left, pkt) || e.evalLogic(expr.Right, pkt)
	case types.LogAnd:
		return e.evalLogic(expr.Left, pkt) && e.evalLogic(expr.Right, pkt)
	case types.LogLt, types.LogGt, types.LogEq:
		lv, _ := strconv.ParseFloat(e.resolveOperand(expr.Left), 64)
		rv, _ := strconv.ParseFloat(e.resolveOperand(expr.Right), 64)
		if expr.Op == types.LogLt {
			return lv < rv
		}
		if expr.Op == types.LogGt {
			return lv > rv
		}
		return lv == rv
	case types.LogMalicious:
		return pkt.IsMalicious
	case types.LogProto:
		return strings.EqualFold(pkt.Protocol, e.resolveOperand(expr.Right))
	case types.LogContains:
		search := strings.Trim(e.resolveOperand(expr.Right), "\" ")
		return strings.Contains(hex.Dump(pkt.Payload), search)
	}
	return false
}

func (e *Engine) resolveOperand(expr *types.LogicExpr) string {
	if expr.Op == types.LogConst {
		return expr.Value
	}
	if expr.Op == types.LogVar {
		return e.expandVars("%"+expr.Value+"%", nil)
	}
	return ""
}

func (e *Engine) killProcess(pkt *types.PacketData) {
	if pkt.PID <= 0 {
		return
	}
	p, err := os.FindProcess(int(pkt.PID))
	if err == nil {
		p.Kill()
	}
}

func (e *Engine) evalMath(expr string) string {
	tokens := make([]string, 0, 8)
	start := -1
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			if start != -1 {
				tokens = append(tokens, expr[start:i])
				start = -1
			}
			continue
		}
		if c == '+' || c == '-' || c == '*' || c == '/' {
			if start != -1 {
				tokens = append(tokens, expr[start:i])
			}
			tokens = append(tokens, string(c))
			start = -1
		} else if start == -1 {
			start = i
		}
	}
	if start != -1 {
		tokens = append(tokens, expr[start:])
	}

	if len(tokens) < 3 {
		return expr
	}

	var highPrec []string
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if (t == "*" || t == "/") && len(highPrec) > 0 {
			left, _ := strconv.ParseFloat(highPrec[len(highPrec)-1], 64)
			i++
			if i >= len(tokens) {
				break
			}
			right, _ := strconv.ParseFloat(tokens[i], 64)
			var res float64
			if t == "*" {
				res = left * right
			} else if right != 0 {
				res = left / right
			}
			highPrec[len(highPrec)-1] = strconv.FormatFloat(res, 'f', 9, 64)
		} else {
			highPrec = append(highPrec, t)
		}
	}

	if len(highPrec) == 0 {
		return "0"
	}
	total, _ := strconv.ParseFloat(highPrec[0], 64)
	for i := 1; i < len(highPrec); i += 2 {
		if i+1 >= len(highPrec) {
			break
		}
		op := highPrec[i]
		val, _ := strconv.ParseFloat(highPrec[i+1], 64)
		switch op {
		case "+":
			total += val
		case "-":
			total -= val
		}
	}

	return strconv.FormatFloat(total, 'f', 9, 64)
}

func (e *Engine) parseTemplate(input string) []string {
	var parts []string
	curr := input
	for {
		idx := strings.IndexByte(curr, '%')
		if idx == -1 {
			parts = append(parts, curr)
			break
		}
		parts = append(parts, curr[:idx])
		curr = curr[idx+1:]
		end := strings.IndexByte(curr, '%')
		if end == -1 {
			parts = append(parts, "%"+curr)
			break
		}
		parts = append(parts, curr[:end])
		curr = curr[end+1:]
	}
	return parts
}

func (e *Engine) writeExpanded(w io.Writer, ins *types.Instruction, pkt *types.PacketData) {
	parts := ins.TemplateParts
	if len(parts) == 0 {
		io.WriteString(w, convertMinecraftColors(e.expandVars(ins.Message, pkt)))
		return
	}

	var sw io.StringWriter
	if s, ok := w.(io.StringWriter); ok {
		sw = s
	}

	var b [20]byte
	for i, p := range parts {
		if i%2 == 0 {
			if sw != nil {
				sw.WriteString(p)
			} else {
				io.WriteString(w, p)
			}
		} else {
			handled := false
			if pkt != nil {
				switch p {
				case "ITER":
					w.Write(strconv.AppendInt(b[:0], int64(pkt.Iteration), 10))
					handled = true
				case "CORE":
					w.Write(strconv.AppendInt(b[:0], int64(pkt.Core), 10))
					handled = true
				case "SRC_IP":
					if sw != nil {
						sw.WriteString(pkt.SrcIP)
					} else {
						w.Write([]byte(pkt.SrcIP))
					}
					handled = true
				case "DST_IP":
					if sw != nil {
						sw.WriteString(pkt.DstIP)
					} else {
						w.Write([]byte(pkt.DstIP))
					}
					handled = true
				}
			}
			if !handled {
				var v string
				var vOk bool
				if pkt != nil && pkt.LocalVars != nil {
					v, vOk = pkt.LocalVars[p]
				} else {
					e.mu.RLock()
					v, vOk = e.Vars[p]
					e.mu.RUnlock()
				}
				if !vOk {
					if sw != nil {
						sw.WriteString("%" + p + "%")
					} else {
						w.Write([]byte("%" + p + "%"))
					}
				} else {
					if sw != nil {
						sw.WriteString(v)
					} else {
						w.Write([]byte(v))
					}
				}
			}
		}
	}
}

func convertMinecraftColors(input string) string {
	if !strings.Contains(input, "&") {
		return input
	}
	replacer := strings.NewReplacer(
		"&0", "\x1b[30m", "&1", "\x1b[34m", "&2", "\x1b[32m", "&3", "\x1b[36m",
		"&4", "\x1b[31m", "&5", "\x1b[35m", "&6", "\x1b[33m", "&7", "\x1b[37m",
		"&8", "\x1b[90m", "&9", "\x1b[94m", "&a", "\x1b[92m", "&b", "\x1b[96m",
		"&c", "\x1b[91m", "&d", "\x1b[95m", "&e", "\x1b[93m", "&f", "\x1b[97m",
		"&l", "\x1b[1m", "&m", "\x1b[9m", "&n", "\x1b[4m", "&o", "\x1b[3m",
		"&r", "\x1b[0m",
	)
	return replacer.Replace(input)
}

func (e *Engine) expandVars(input string, pkt *types.PacketData) string {
	input = strings.ReplaceAll(input, "\\033", "\x1b")
	if !strings.Contains(input, "%") {
		return convertMinecraftColors(input)
	}

	var sb strings.Builder
	curr := input
	for {
		idx := strings.IndexByte(curr, '%')
		if idx == -1 {
			sb.WriteString(curr)
			break
		}
		sb.WriteString(curr[:idx])
		curr = curr[idx+1:]
		end := strings.IndexByte(curr, '%')
		if end == -1 {
			sb.WriteByte('%')
			sb.WriteString(curr)
			break
		}
		key := curr[:end]

		handled := false
		if pkt != nil {
			switch key {
			case "ITER":
				var b [20]byte
				sb.Write(strconv.AppendInt(b[:0], int64(pkt.Iteration), 10))
				handled = true
			case "CORE":
				var b [20]byte
				sb.Write(strconv.AppendInt(b[:0], int64(pkt.Core), 10))
				handled = true
			case "SRC_IP":
				sb.WriteString(pkt.SrcIP)
				handled = true
			case "DST_IP":
				sb.WriteString(pkt.DstIP)
				handled = true
			case "PROTO":
				sb.WriteString(pkt.Protocol)
				handled = true
			case "PROCESS":
				sb.WriteString(pkt.ProcessName)
				handled = true
			case "PID":
				var b [20]byte
				sb.Write(strconv.AppendInt(b[:0], int64(pkt.PID), 10))
				handled = true
			}
		}

		if !handled {
			var val string
			var ok bool
			if pkt != nil && pkt.LocalVars != nil {
				val, ok = pkt.LocalVars[key]
			} else {
				e.mu.RLock()
				val, ok = e.Vars[key]
				e.mu.RUnlock()
			}

			if !ok {
				sb.WriteByte('%')
				sb.WriteString(key)
				sb.WriteByte('%')
			} else {
				f, err := strconv.ParseFloat(val, 64)
				if err == nil && f > 0 && f < 1 {
					if strings.HasPrefix(curr[end+1:], "ms") {
						if f < 0.001 {
							sb.WriteString(strconv.FormatFloat(f*1000000, 'f', 4, 64))
							sb.WriteString(" nanoseconds")
						} else {
							sb.WriteString(strconv.FormatFloat(f*1000, 'f', 4, 64))
							sb.WriteString(" microseconds")
						}
						curr = curr[end+3:]
						continue
					} else if strings.HasPrefix(curr[end+1:], "s") {
						next := curr[end+1:]
						if len(next) == 1 || next[1] == ' ' || next[1] == '\n' || next[1] == '\t' || next[1] == '.' || next[1] == ',' {
							if f < 0.000001 {
								sb.WriteString(strconv.FormatFloat(f*1000000000, 'f', 4, 64))
								sb.WriteString(" nanoseconds")
							} else if f < 0.001 {
								sb.WriteString(strconv.FormatFloat(f*1000000, 'f', 4, 64))
								sb.WriteString(" microseconds")
							} else {
								sb.WriteString(strconv.FormatFloat(f*1000, 'f', 4, 64))
								sb.WriteString(" ms")
							}
							curr = curr[end+2:]
							continue
						}
					}
				}
				sb.WriteString(val)
			}
		}
		curr = curr[end+1:]
	}
	return convertMinecraftColors(sb.String())
}

func (e *Engine) executeBound(bound []boundHandler, pkt *types.PacketData, lastIfMet *bool) bool {
	for _, bh := range bound {
		if bh.h(e, bh.ins, pkt, lastIfMet) {
			return true
		}
	}
	return false
}
