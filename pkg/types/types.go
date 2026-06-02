package types

import (
	"io"
	"time"
)

type OpCode uint8

const (
	OpNop OpCode = iota
	OpUse
	OpTimerStart
	OpTimerEnd
	OpSet
	OpSetExpr
	OpSetHeader
	OpGetHeader
	OpGetISP
	OpTime
	OpBreak
	OpIncrement
	OpLoop
	OpWhile
	OpSystem
	OpData
	OpTelemetry
	OpFilter
	OpReject
	OpBashKill
	OpNuke
	OpDropAll
	OpRedirect
	OpSpoof
	OpAlert
	OpExec
	OpInput
	OpPost
	OpIfComplex
	OpSleep
	OpCall
	OpPrint
	OpLog
	OpFetch
	OpIfMalicious
	OpIfProto
	OpIfExt
	OpIfExtCall
	OpIfMaliciousCall
	OpElse
	OpBlock
	OpIfMaliciousBlock
	OpIfPrint
	OpIfCall
	OpIfBlock
	OpIfExec
	OpIfPost
	OpIfBreak
	OpParallelLoop
	OpSearch
	OpReadFile
	OpTokenize
	OpArrayGet
	OpArraySet
	OpArrayLen
	OpIndexOf
)

type LogicOp uint8

const (
	LogNop LogicOp = iota
	LogOr
	LogAnd
	LogLt
	LogGt
	LogEq
	LogContains
	LogProto
	LogMalicious
	LogExt
	LogVar
	LogConst
)

type LogicExpr struct {
	Op    LogicOp
	Left  *LogicExpr
	Right *LogicExpr
	Value string
	Int   int
}

type Instruction struct {
	Op        OpCode
	Value     string
	Message   string
	Body      []Instruction
	Condition *LogicExpr
	IntValue  int
	IsStatic  bool
	Duration  time.Duration
}

type CompiledScript struct {
	Main      []Instruction
	Functions map[string][]Instruction
	Imports   []string
	Symbols   []string
}

type PacketData struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcMAC      string
	DstMAC      string
	SrcPort     string
	DstPort     string
	Protocol    string
	Length      int
	ISP         string
	Service     string
	Payload     []byte
	ProcessName string
	Hostname    string
	PID         int32
	AIAnalysis  string
	IsMalicious bool
	HTTPHeaders map[string]string
	HTTPStatus  string
	HTTPMethod  string
	Iteration   int
	Core        int
	Writer      io.Writer
	LocalVars   map[string]string
}

type Plugin interface {
	Name() string
	OnPacket(pkt *PacketData)
}
