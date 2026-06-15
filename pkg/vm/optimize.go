package vm

import (
	"strconv"
	"strings"

	"sharkscript/pkg/types"
)

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
