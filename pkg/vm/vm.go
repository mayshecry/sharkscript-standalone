package vm

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
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
	Filename      string
	Instructions  []types.Instruction
	Functions     map[string][]types.Instruction
	Imports       map[string]bool
	Vars          map[string]string
	Headers       map[string]string
	TimerStart    time.Time
	mu            sync.RWMutex
	out           *bufio.Writer
	outMu         sync.Mutex
	logPrefix     string
	corePrefixes  []string
	basedPrefixes []string
}

type boundHandler struct {
	h   instructionHandler
	ins types.Instruction
}

func NewEngine(script types.CompiledScript, filename string) *Engine {
	e := &Engine{
		Filename:     filename,
		Instructions: script.Main,
		Functions:    script.Functions,
		Imports:      make(map[string]bool),
		Vars:         make(map[string]string),
		Headers:      make(map[string]string),
		out:          bufio.NewWriterSize(os.Stdout, 128*1024),
		logPrefix:    "[" + filename + "] ",
	}
	for _, imp := range script.Imports {
		e.Imports[imp] = true
	}

	e.corePrefixes = make([]string, 129)
	e.basedPrefixes = make([]string, 129)
	for i := 0; i < 129; i++ {
		p := "[" + filename + "] "
		if i > 0 {
			p = fmt.Sprintf("[%s] [Core %d] ", filename, i)
		}
		e.corePrefixes[i] = p
		e.basedPrefixes[i] = p + "🗿 BASED: "
	}

	return e
}

func (e *Engine) Run(pkt *types.PacketData) {
	e.execute(e.Instructions, pkt)
	e.out.Flush()
}

type instructionHandler func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool

var opTable [256]instructionHandler

func init() {
	opTable[types.OpWhile] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		for e.evalLogic(ins.Condition, pkt) {
			if e.execute(ins.Body, pkt) {
				break
			}
		}
		return false
	}
	opTable[types.OpTimerStart] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		e.mu.Lock()
		e.TimerStart = time.Now()
		e.mu.Unlock()
		return false
	}
	opTable[types.OpTimerEnd] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		e.mu.RLock()
		duration := time.Since(e.TimerStart).Seconds()
		e.mu.RUnlock()
		e.mu.Lock()
		e.Vars[ins.Value] = strconv.FormatFloat(duration, 'f', 9, 64)
		e.mu.Unlock()
		return false
	}
	opTable[types.OpSet] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		val := e.expandVars(ins.Message, pkt)
		e.mu.Lock()
		e.Vars[ins.Value] = val
		e.mu.Unlock()
		return false
	}
	opTable[types.OpSetExpr] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		val := e.evalMath(e.expandVars(ins.Message, pkt))
		e.mu.Lock()
		e.Vars[ins.Value] = val
		e.mu.Unlock()
		return false
	}
	opTable[types.OpIncrement] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		e.mu.Lock()
		curr := e.Vars[ins.Value]
		iv, _ := strconv.Atoi(curr)
		e.Vars[ins.Value] = strconv.Itoa(iv + 1)
		e.mu.Unlock()
		return false
	}
	opTable[types.OpLoop] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if len(ins.Body) == 0 {
			count := ins.IntValue
			if !ins.IsStatic {
				count, _ = strconv.Atoi(e.expandVars(ins.Value, pkt))
			}
			for i := 0; i < count; i++ {
			}
			return false
		}
		needsIter := e.containsIter(ins.Body)

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
				if e.execute(ins.Body, pkt) {
					return true
				}
			}
			return false
		}

		count := ins.IntValue
		if !ins.IsStatic {
			count, _ = strconv.Atoi(e.expandVars(ins.Value, pkt))
		}
		for i := 0; i < count; i++ {
			if needsIter {
				pkt.Iteration = i
			}
			if e.execute(ins.Body, pkt) {
				return true
			}
		}
		e.out.Flush()
		return false
	}
	opTable[types.OpParallelLoop] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if len(ins.Body) == 0 {
			count := ins.IntValue
			if !ins.IsStatic {
				count, _ = strconv.Atoi(e.expandVars(ins.Value, pkt))
			}
			if count <= 0 {
				return false
			}
			return false
		}

		e.mu.RLock()
		snapshot := make(map[string]string, len(e.Vars))
		for k, v := range e.Vars {
			snapshot[k] = v
		}
		e.mu.RUnlock()

		boundBody := make([]boundHandler, len(ins.Body))
		for i, bIns := range ins.Body {
			boundBody[i] = boundHandler{h: opTable[bIns.Op], ins: bIns}
		}

		needsIter := e.containsIter(ins.Body)
		numWorkers := runtime.GOMAXPROCS(0)

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
				buffers[w] = bytes.NewBuffer(make([]byte, 0, 1024*1024))
				go func(id int, localBuf *bytes.Buffer) {
					defer wg.Done()
					bw := bufio.NewWriterSize(localBuf, 1024*1024)
					lp := *pkt
					lp.Core = id + 1
					lp.Writer = bw
					lp.LocalVars = snapshot
					innerLastIf := false
					var k int
					for ; ; k++ {
						if k&0x3F == 0 && time.Now().After(stop) {
							break
						}
						if needsIter {
							lp.Iteration = k
						}
						for _, bh := range boundBody {
							if bh.h(e, bh.ins, &lp, &innerLastIf) {
								break
							}
						}
					}
					bw.Flush()
					iterCounts[id] = uint64(k)
				}(w, buffers[w])
			}
			wg.Wait()

			var totalIterations uint64
			for _, c := range iterCounts {
				totalIterations += c
			}

			e.outMu.Lock()
			for _, b := range buffers {
				e.out.Write(b.Bytes())
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

		count := ins.IntValue
		if !ins.IsStatic {
			count, _ = strconv.Atoi(e.expandVars(ins.Value, pkt))
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
			buffers[w] = bytes.NewBuffer(make([]byte, 0, (count/numWorkers)*64))
			start := (count * w) / numWorkers
			end := (count * (w + 1)) / numWorkers
			go func(s, n, id int, localBuf *bytes.Buffer) {
				defer wg.Done()
				bw := bufio.NewWriterSize(localBuf, 1024*1024)
				lp := *pkt
				lp.Core = id + 1
				lp.Writer = bw
				lp.LocalVars = snapshot
				innerLastIf := false
				for i := s; i < n; i++ {
					if needsIter {
						lp.Iteration = i
					}
					for _, bh := range boundBody {
						if bh.h(e, bh.ins, &lp, &innerLastIf) {
							break
						}
					}
				}
				bw.Flush()
			}(start, end, w, buffers[w])
		}
		wg.Wait()
		elapsed := time.Since(startLoop)

		e.outMu.Lock()
		for _, b := range buffers {
			e.out.Write(b.Bytes())
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
	opTable[types.OpPrint] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		msg := e.expandVars(ins.Message, pkt)
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
		return false
	}
	opTable[types.OpBased] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		msg := e.expandVars(ins.Message, pkt)
		idx := 0
		if pkt != nil && pkt.Core > 0 && pkt.Core < 129 {
			idx = pkt.Core
		}

		if pkt != nil && pkt.Writer != nil {
			pkt.Writer.Write([]byte(e.basedPrefixes[idx]))
			pkt.Writer.Write([]byte(msg))
			pkt.Writer.Write([]byte{'\n'})
			return false
		}

		e.outMu.Lock()
		e.out.WriteString(e.basedPrefixes[idx])
		e.out.WriteString(msg)
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
		go cmd.Run()
		return false
	}
	opTable[types.OpTime] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		e.mu.Lock()
		ms := float64(time.Now().UnixNano()) / 1e6
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
			msg := e.expandVars(ins.Message, pkt)
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
	expr = strings.ReplaceAll(expr, " ", "")
	var tokens []string
	var buf strings.Builder

	for _, r := range expr {
		if strings.ContainsRune("+-*/", r) {
			if buf.Len() > 0 {
				tokens = append(tokens, buf.String())
				buf.Reset()
			}
			tokens = append(tokens, string(r))
		} else {
			buf.WriteRune(r)
		}
	}
	if buf.Len() > 0 {
		tokens = append(tokens, buf.String())
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
		if op == "+" {
			total += val
		} else if op == "-" {
			total -= val
		}
	}

	return strconv.FormatFloat(total, 'f', 9, 64)
}

func (e *Engine) expandVars(input string, pkt *types.PacketData) string {
	if !strings.Contains(input, "%") {
		return input
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
				sb.WriteString("%" + key + "%")
			} else {
				f, err := strconv.ParseFloat(val, 64)
				if err == nil && f > 0 && f < 1 {
					if strings.HasPrefix(curr[end+1:], "ms") {
						if f < 0.001 {
							sb.WriteString(strconv.FormatFloat(f*1000000, 'f', 4, 64) + " nanoseconds")
						} else {
							sb.WriteString(strconv.FormatFloat(f*1000, 'f', 4, 64) + " microseconds")
						}
						curr = curr[end+3:]
						continue
					} else if strings.HasPrefix(curr[end+1:], "s") {
						next := curr[end+1:]
						if len(next) == 1 || next[1] == ' ' || next[1] == '\n' || next[1] == '\t' || next[1] == '.' || next[1] == ',' {
							if f < 0.000001 {
								sb.WriteString(strconv.FormatFloat(f*1000000000, 'f', 4, 64) + " nanoseconds")
							} else if f < 0.001 {
								sb.WriteString(strconv.FormatFloat(f*1000000, 'f', 4, 64) + " microseconds")
							} else {
								sb.WriteString(strconv.FormatFloat(f*1000, 'f', 4, 64) + " ms")
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
	return sb.String()
}
