package vm

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"sharkscript/pkg/types"
)

type Engine struct {
	Filename     string
	Instructions []types.Instruction
	Functions    map[string][]types.Instruction
	Imports      map[string]bool
	Vars         map[string]string
	Headers      map[string]string
	TimerStart   time.Time
	mu           sync.RWMutex
}

func NewEngine(script types.CompiledScript, filename string) *Engine {
	e := &Engine{
		Filename:     filename,
		Instructions: script.Main,
		Functions:    script.Functions,
		Imports:      make(map[string]bool),
		Vars:         make(map[string]string),
		Headers:      make(map[string]string),
	}
	for _, imp := range script.Imports {
		e.Imports[imp] = true
	}
	return e
}

func (e *Engine) Run(pkt *types.PacketData) {
	e.mu.Lock()
	e.Vars["SRC_IP"] = pkt.SrcIP
	e.Vars["DST_IP"] = pkt.DstIP
	e.Vars["PROTO"] = pkt.Protocol
	e.Vars["PROCESS"] = pkt.ProcessName
	e.Vars["PID"] = fmt.Sprintf("%d", pkt.PID)
	e.mu.Unlock()

	e.execute(e.Instructions, pkt)
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
		e.Vars[ins.Value] = strconv.FormatFloat(duration, 'f', 4, 64)
		e.mu.Unlock()
		return false
	}
	opTable[types.OpSet] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		val := e.expandVars(ins.Message)
		e.mu.Lock()
		e.Vars[ins.Value] = val
		e.mu.Unlock()
		return false
	}
	opTable[types.OpSetExpr] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		val := e.evalMath(e.expandVars(ins.Message))
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
			return false
		}

		dur := ins.Duration
		if !ins.IsStatic {
			val := strings.ToLower(e.expandVars(ins.Value))
			val = strings.ReplaceAll(val, "min", "m")
			if d, err := time.ParseDuration(val); err == nil {
				dur = d
			}
		}

		if dur > 0 {
			for stop := time.Now().Add(dur); time.Now().Before(stop); {
				if e.execute(ins.Body, pkt) {
					return true
				}
			}
			return false
		}

		count := ins.IntValue
		if !ins.IsStatic {
			count, _ = strconv.Atoi(e.expandVars(ins.Value))
		}
		for i := 0; i < count; i++ {
			if e.execute(ins.Body, pkt) {
				return true
			}
		}
		return false
	}
	opTable[types.OpParallelLoop] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if len(ins.Body) == 0 {
			return false
		}

		dur := ins.Duration
		if !ins.IsStatic {
			val := strings.ToLower(e.expandVars(ins.Value))
			val = strings.ReplaceAll(val, "min", "m")
			if d, err := time.ParseDuration(val); err == nil {
				dur = d
			}
		}

		if dur > 0 {
			numWorkers := runtime.GOMAXPROCS(0)
			var wg sync.WaitGroup
			wg.Add(numWorkers)
			stop := time.Now().Add(dur)
			for w := 0; w < numWorkers; w++ {
				go func() {
					defer wg.Done()
					for time.Now().Before(stop) {
						e.execute(ins.Body, pkt)
					}
				}()
			}
			wg.Wait()
			return false
		}

		count := ins.IntValue
		if !ins.IsStatic {
			count, _ = strconv.Atoi(e.expandVars(ins.Value))
		}
		if count <= 0 {
			return false
		}
		numWorkers := runtime.NumCPU()
		if count < numWorkers {
			numWorkers = count
		}

		var wg sync.WaitGroup
		wg.Add(numWorkers)
		for w := 0; w < numWorkers; w++ {
			workerID := w
			go func() {
				defer wg.Done()
				start, end := (count*workerID)/numWorkers, (count*(workerID+1))/numWorkers
				for i := start; i < end; i++ {
					e.execute(ins.Body, pkt)
				}
			}()
		}
		wg.Wait()
		return false
	}
	opTable[types.OpPrint] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		fmt.Printf("[%s] %s\n", e.Filename, e.expandVars(ins.Message))
		return false
	}
	opTable[types.OpBased] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		fmt.Printf("[%s] 🗿 BASED: %s\n", e.Filename, e.expandVars(ins.Message))
		return false
	}
	opTable[types.OpExec] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		expanded := e.expandVars(ins.Message)
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
		e.Vars[ins.Value] = strconv.FormatFloat(ms, 'f', 4, 64)
		e.mu.Unlock()
		return false
	}
	opTable[types.OpSleep] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		if ms, err := strconv.Atoi(e.expandVars(ins.Value)); err == nil {
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		return false
	}
	opTable[types.OpLog] = func(e *Engine, ins types.Instruction, pkt *types.PacketData, lastIfMet *bool) bool {
		msg := e.expandVars(ins.Message)
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
			fmt.Printf("[%s] %s\n", e.Filename, e.expandVars(ins.Message))
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
	msg := e.expandVars(ins.Message)
	switch ins.Value {
	case "ELSE_PRINT":
		fmt.Printf("[%s] %s\n", e.Filename, msg)
	case "ELSE_CALL":
		if f, ok := e.Functions[msg]; ok {
			return e.execute(f, pkt)
		}
	case "ELSE_BLOCK":
		e.killProcess(pkt)
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
		return e.expandVars("%" + expr.Value + "%")
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
			highPrec[len(highPrec)-1] = strconv.FormatFloat(res, 'f', 4, 64)
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

	return strconv.FormatFloat(total, 'f', 4, 64)
}

func (e *Engine) expandVars(input string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
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
		if val, ok := e.Vars[key]; ok {
			sb.WriteString(val)
		} else {
			sb.WriteString("%" + key + "%")
		}
		curr = curr[end+1:]
	}
	return sb.String()
}
