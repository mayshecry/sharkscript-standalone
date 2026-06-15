package vm

import (
	"encoding/hex"
	"io"
	"strconv"
	"strings"

	"sharkscript/pkg/types"
)

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
