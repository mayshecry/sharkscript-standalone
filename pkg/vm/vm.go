package vm

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

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

func (e *Engine) killProcess(pkt *types.PacketData) {
	if pkt.PID <= 0 {
		return
	}
	p, err := os.FindProcess(int(pkt.PID))
	if err == nil {
		p.Kill()
	}
}

func (e *Engine) executeBound(bound []boundHandler, pkt *types.PacketData, lastIfMet *bool) bool {
	for _, bh := range bound {
		if bh.h(e, bh.ins, pkt, lastIfMet) {
			return true
		}
	}
	return false
}
