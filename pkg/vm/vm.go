package vm

import (
	"bufio"
	"bytes"
	"encoding/hex"
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

type Engine struct {
	Filename            string
	Instructions        []types.Instruction
	Functions           map[string][]types.Instruction
	Imports             map[string]bool
	Vars                map[string]string
	Arrays              map[string][]string
	Headers             map[string]string
	Timers              map[string]time.Time
	Registers           []string
	RegMap              map[string]int
	NoOptimize          bool
	mu                  sync.RWMutex
	DiscordLimitChannel string
	HasBackgroundTasks  bool
	out                 *bufio.Writer
	NumWorkers          int
	outMu               sync.Mutex
	UsesBypassTime      bool
	bufferPool          sync.Pool
	logPrefix           string
	templateCache       sync.Map
	corePrefixes        []string
	corePrefixBytes     [][]byte
	systemPrefixes      []string
	systemPrefixBytes   [][]byte
}

type bakedOp struct {
	static []byte
	regID  int
}

type boundHandler struct {
	h   instructionHandler
	ins types.Instruction
}

func NewEngine(script types.CompiledScript, filename string, noOptimize bool) *Engine {
	e := &Engine{
		Filename:       filename,
		Instructions:   script.Main,
		Functions:      script.Functions,
		Imports:        make(map[string]bool),
		Vars:           make(map[string]string),
		Arrays:         make(map[string][]string),
		Headers:        make(map[string]string),
		Timers:         make(map[string]time.Time),
		Registers:      make([]string, 1024),
		RegMap:         make(map[string]int),
		NoOptimize:     noOptimize,
		out:            bufio.NewWriterSize(os.Stdout, 5*1024*1024),
		NumWorkers:     runtime.GOMAXPROCS(0),
		UsesBypassTime: script.UsesBypassTime,
		bufferPool: sync.Pool{
			New: func() any { return bytes.NewBuffer(make([]byte, 0, 5*1024*1024)) },
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

	e.Instructions = e.bake(e.Instructions)
	for name, fn := range e.Functions {
		e.Functions[name] = e.bake(fn)
	}

	return e
}

func (e *Engine) getRegID(name string) int {
	if id, ok := e.RegMap[name]; ok {
		return id
	}
	id := len(e.RegMap)
	e.RegMap[name] = id
	if id >= len(e.Registers) {
		e.Registers = append(e.Registers, "")
	}
	return id
}

func (e *Engine) bake(insts []types.Instruction) []types.Instruction {
	if !e.NoOptimize {
		insts = optimizePeephole(insts)
		insts = unrollLoops(insts)
		insts, _ = mergePrints(insts)
	}

	for i := range insts {
		ins := &insts[i]

		// Pre-resolve variable targets to Register IDs
		if ins.Op == types.OpSet || ins.Op == types.OpSetExpr || ins.Op == types.OpIncrement || ins.Op == types.OpTimerEnd || ins.Op == types.OpInput {
			ins.IntValue = e.getRegID(ins.Value)
		}

		if strings.Contains(ins.Message, "%") {
			parts := parseTemplate(ins.Message)
			bOps := make([]bakedOp, len(parts))
			for j, p := range parts {
				if j%2 == 0 {
					bOps[j] = bakedOp{static: []byte(convertMinecraftColors(p))}
				} else {
					switch p {
					case "ITER":
						bOps[j] = bakedOp{regID: -1}
					case "CORE":
						bOps[j] = bakedOp{regID: -2}
					default:
						bOps[j] = bakedOp{regID: e.getRegID(p)}
					}
				}
			}
			ins.RuntimeState = bOps
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
			ins.Body = e.bake(ins.Body)
			if ins.Op == types.OpWhile || ins.Op == types.OpLoop || ins.Op == types.OpParallelLoop || ins.Op == types.OpIfComplex {
				bound := make([]boundHandler, len(ins.Body))
				for j, bIns := range ins.Body {
					bound[j] = boundHandler{h: opTable[bIns.Op], ins: bIns}
				}
				ins.RuntimeState = bound
			}
		}
	}
	return insts
}

func (e *Engine) Run(pkt *types.PacketData) {
	e.mu.Lock()
	if pkt.Registers == nil {
		pkt.Registers = make([]string, len(e.Registers))
		copy(pkt.Registers, e.Registers)
	}
	for k, v := range e.Vars {
		pkt.Registers[e.getRegID(k)] = v
	}
	e.mu.Unlock()
	e.execute(e.Instructions, pkt)
	e.out.Flush()
	if e.HasBackgroundTasks {
		select {}
	}
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
	case types.LogLt, types.LogGt, types.LogEq, types.LogNe:
		ls := e.resolveOperand(expr.Left, pkt)
		rs := e.resolveOperand(expr.Right, pkt)

		li, lErrI := strconv.ParseInt(ls, 10, 64)
		ri, rErrI := strconv.ParseInt(rs, 10, 64)
		if lErrI == nil && rErrI == nil {
			switch expr.Op {
			case types.LogLt:
				return li < ri
			case types.LogGt:
				return li > ri
			case types.LogEq:
				return li == ri
			case types.LogNe:
				return li != ri
			}
		}

		lf, lErrF := strconv.ParseFloat(ls, 64)
		rf, rErrF := strconv.ParseFloat(rs, 64)
		if lErrF == nil && rErrF == nil {
			switch expr.Op {
			case types.LogLt:
				return lf < rf
			case types.LogGt:
				return lf > rf
			case types.LogEq:
				return lf == rf
			case types.LogNe:
				return lf != rf
			}
		}

		switch expr.Op {
		case types.LogEq:
			return ls == rs
		case types.LogNe:
			return ls != rs
		}
		return false
	case types.LogMalicious:
		return pkt.IsMalicious
	case types.LogProto:
		return strings.EqualFold(pkt.Protocol, e.resolveOperand(expr.Right, pkt))
	case types.LogContains:
		search := strings.Trim(e.resolveOperand(expr.Right, pkt), "\" ")
		return strings.Contains(hex.Dump(pkt.Payload), search)
	}
	return false
}

func (e *Engine) resolveOperand(expr *types.LogicExpr, pkt *types.PacketData) string {
	if expr.Op == types.LogConst {
		return expr.Value
	}
	if expr.Op == types.LogVar {
		return e.expandVars("%"+expr.Value+"%", pkt)
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
	tokenize := func(s string) []string {
		var t []string
		start := -1
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				if start != -1 {
					t = append(t, s[start:i])
					start = -1
				}
				continue
			}
			if c == '+' || c == '-' || c == '*' || c == '/' || c == '%' || c == '(' || c == ')' {
				if start != -1 {
					t = append(t, s[start:i])
				}
				t = append(t, string(c))
				start = -1
			} else if start == -1 {
				start = i
			}
		}
		if start != -1 {
			t = append(t, s[start:])
		}
		return t
	}
	solve := func(tokens []string) string {
		if len(tokens) == 0 {
			return "0"
		}
		hp := make([]string, 0, len(tokens))
		for i := 0; i < len(tokens); i++ {
			t := tokens[i]
			if (t == "*" || t == "/" || t == "%") && len(hp) > 0 {
				l, _ := strconv.ParseFloat(hp[len(hp)-1], 64)
				i++
				if i >= len(tokens) {
					break
				}
				r, _ := strconv.ParseFloat(tokens[i], 64)
				var res float64
				if t == "*" {
					res = l * r
				} else if r != 0 {
					if t == "/" {
						res = l / r
					} else {
						res = float64(int64(l) % int64(r))
					}
				}
				hp[len(hp)-1] = strconv.FormatFloat(res, 'f', 18, 64)
			} else {
				hp = append(hp, t)
			}
		}
		if len(hp) == 0 {
			return "0"
		}
		tot, _ := strconv.ParseFloat(hp[0], 64)
		for i := 1; i < len(hp); i += 2 {
			if i+1 >= len(hp) {
				break
			}
			op := hp[i]
			v, _ := strconv.ParseFloat(hp[i+1], 64)
			if op == "+" {
				tot += v
			} else {
				tot -= v
			}
		}
		return strconv.FormatFloat(tot, 'f', 18, 64)
	}
	tokens := tokenize(expr)
	for {
		o, c := -1, -1
		for i, t := range tokens {
			if t == "(" {
				o = i
			} else if t == ")" {
				c = i
				break
			}
		}
		if o != -1 && c != -1 {
			sub := solve(tokens[o+1 : c])
			nt := append(tokens[:o], sub)
			tokens = append(nt, tokens[c+1:]...)
			continue
		}
		break
	}
	return solve(tokens)
}

func parseTemplate(input string) []string {
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

func (e *Engine) streamBaked(w io.Writer, ins *types.Instruction, pkt *types.PacketData) {
	ops, ok := ins.RuntimeState.([]bakedOp)
	if !ok {
		w.Write([]byte(convertMinecraftColors(ins.Message)))
		return
	}
	var scratch [32]byte
	regs := e.Registers
	if pkt != nil && pkt.Registers != nil {
		regs = pkt.Registers
	} else {
		e.mu.RLock()
		defer e.mu.RUnlock()
	}
	for _, op := range ops {
		if op.static != nil {
			w.Write(op.static)
			continue
		}
		if op.regID >= 0 {
			w.Write([]byte(regs[op.regID]))
			continue
		}
		switch op.regID {
		case -1:
			w.Write(strconv.AppendInt(scratch[:0], int64(pkt.Iteration), 10))
		case -2:
			w.Write(strconv.AppendInt(scratch[:0], int64(pkt.Core), 10))
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
	if !strings.Contains(input, "%") && !strings.Contains(input, "\\033") {
		return convertMinecraftColors(input)
	}
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
			if id, exists := e.RegMap[key]; exists {
				if pkt != nil && pkt.Registers != nil {
					val = pkt.Registers[id]
				} else {
					e.mu.RLock()
					val = e.Registers[id]
					e.mu.RUnlock()
				}
				ok = true
			} else if pkt != nil && pkt.LocalVars != nil {
				val, ok = pkt.LocalVars[key]
			} else {
				e.mu.RLock()
				val, ok = e.Vars[key]
				e.mu.RUnlock()
			}

			if !ok {
			} else {
				f, err := strconv.ParseFloat(val, 64)
				if err == nil && f > 0 && f < 1 {
					if strings.HasPrefix(curr[end+1:], "ms") {
						if key == "BYPASS_TIME" {
							sb.WriteString(strconv.FormatFloat(f*1000000, 'f', 4, 64))
							sb.WriteString(" nanoseconds")
						} else if f < 0.000000001 {
							sb.WriteString(strconv.FormatFloat(f*1000000000000, 'f', 4, 64))
							sb.WriteString(" femtoseconds")
						} else if f < 0.000001 {
							sb.WriteString(strconv.FormatFloat(f*1000000000, 'f', 4, 64))
							sb.WriteString(" picoseconds")
						} else if f < 0.001 {
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
							if f < 0.000000000001 {
								sb.WriteString(strconv.FormatFloat(f*1000000000000000, 'f', 4, 64))
								sb.WriteString(" femtoseconds")
							} else if f < 0.000000001 {
								sb.WriteString(strconv.FormatFloat(f*1000000000000, 'f', 4, 64))
								sb.WriteString(" picoseconds")
							} else if f < 0.000001 {
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

func unrollLoops(insts []types.Instruction) []types.Instruction {
	out := make([]types.Instruction, 0, len(insts))
	for _, ins := range insts {
		if ins.Op == types.OpLoop && ins.IsStatic && ins.IntValue > 0 && ins.IntValue <= 8 {
			for i := 0; i < ins.IntValue; i++ {
				iterStr := strconv.Itoa(i)
				for _, bIns := range ins.Body {
					cloned := bIns
					cloned.Message = strings.ReplaceAll(cloned.Message, "%ITER%", iterStr)
					cloned.Value = strings.ReplaceAll(cloned.Value, "%ITER%", iterStr)
					if len(cloned.Body) > 0 {
						cloned.Body = unrollLoops(cloned.Body)
					}
					out = append(out, cloned)
				}
			}
			continue
		}
		if len(ins.Body) > 0 {
			ins.Body = unrollLoops(ins.Body)
		}
		out = append(out, ins)
	}
	return out
}

func optimizePeephole(insts []types.Instruction) []types.Instruction {
	if len(insts) < 2 {
		return insts
	}

	out := make([]types.Instruction, 0, len(insts))
	for i := 0; i < len(insts); i++ {
		ins := insts[i]

		if i+1 < len(insts) {
			next := insts[i+1]

			if ins.Op == types.OpSet && next.Op == types.OpIncrement && ins.Value == next.Value {
				if val, err := strconv.Atoi(ins.Message); err == nil {
					ins.Message = strconv.Itoa(val + 1)
					out = append(out, ins)
					i++
					continue
				}
			}

			if (ins.Op == types.OpSet || ins.Op == types.OpSetExpr) &&
				(next.Op == types.OpSet || next.Op == types.OpSetExpr) &&
				ins.Value == next.Value {
				continue
			}
		}

		if len(ins.Body) > 0 {
			ins.Body = optimizePeephole(ins.Body)
		}
		out = append(out, ins)
	}
	return out
}

func mergePrints(insts []types.Instruction) ([]types.Instruction, []string) {
	var tips []string
	if len(insts) == 0 {
		return insts, tips
	}

	res := make([]types.Instruction, 0, len(insts))
	for i := 0; i < len(insts); i++ {
		ins := insts[i]
		if ins.Op == types.OpPrint {
			j := i + 1
			merged := 0
			for j < len(insts) && insts[j].Op == types.OpPrint {
				ins.Message += "\n" + insts[j].Message
				j++
				merged++
			}
			if merged > 0 {
				ins.IsStatic = !strings.Contains(ins.Message, "%")
				if !ins.IsStatic {
					ins.TemplateParts = parseTemplate(ins.Message)
				}
				i = j - 1
			}
		}
		if len(ins.Body) > 0 {
			var subTips []string
			ins.Body, subTips = mergePrints(ins.Body)
			tips = append(tips, subTips...)
		}
		res = append(res, ins)
	}
	return res, tips
}

func (e *Engine) executeBound(bound []boundHandler, pkt *types.PacketData, lastIfMet *bool) bool {
	for _, bh := range bound {
		if bh.h(e, bh.ins, pkt, lastIfMet) {
			return true
		}
	}
	return false
}
