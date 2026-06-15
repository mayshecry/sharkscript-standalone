package compiler

import (
	"fmt"
	"strconv"
	"strings"

	"sharkscript/pkg/types"
)

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

		// Detect Math Loop Pattern: [PARALLEL] LOOP N { %X% = (%X% * A + B) % M }
		if (ins.Op == types.OpLoop || ins.Op == types.OpParallelLoop) && len(ins.Body) == 1 {
			isParallel := ins.Op == types.OpParallelLoop
			body := ins.Body[0]
			if body.Op == types.OpSetExpr && strings.Contains(body.Message, "%"+ins.Value+"%") {
				// Basic detection for LCG-style math loops
				// We transform this into a single OpMathLoop instruction
				count, _ := strconv.Atoi(ins.Value)
				if count == 0 {
					count = ins.IntValue
				}

				newIns := types.Instruction{
					Op:             types.OpMathLoop,
					Value:          body.Value,   // The variable being modified
					Message:        body.Message, // The raw expression
					IntValue:       count,
					IsStatic:       true,
					NeedsIteration: isParallel, // Flag for parallel execution
				}
				out = append(out, newIns)
				continue
			}
		}

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

func optimizeUnusedVariables(script *types.CompiledScript) []string {
	reads := make(map[string]bool)

	trackReads := func(s string) {
		if !strings.Contains(s, "%") {
			return
		}
		parts := parseTemplate(s)
		for i := 1; i < len(parts); i += 2 {
			reads[parts[i]] = true
		}
	}

	var findReads func([]types.Instruction)
	findReads = func(insts []types.Instruction) {
		for _, ins := range insts {
			trackReads(ins.Message)
			trackReads(ins.Value)

			if ins.Condition != nil {
				var walkLogic func(*types.LogicExpr)
				walkLogic = func(l *types.LogicExpr) {
					if l == nil {
						return
					}
					if l.Op == types.LogVar {
						reads[l.Value] = true
					}
					walkLogic(l.Left)
					walkLogic(l.Right)
				}
				walkLogic(ins.Condition)
			}
			if ins.Op == types.OpIncrement {
				reads[ins.Value] = true
			}
			if len(ins.Body) > 0 {
				findReads(ins.Body)
			}
		}
	}
	findReads(script.Main)
	for _, f := range script.Functions {
		findReads(f)
	}

	var tips []string
	var sweep func([]types.Instruction) []types.Instruction
	sweep = func(insts []types.Instruction) []types.Instruction {
		out := make([]types.Instruction, 0, len(insts))
		for _, ins := range insts {
			if len(ins.Body) > 0 {
				ins.Body = sweep(ins.Body)
			}
			if (ins.Op == types.OpSet || ins.Op == types.OpSetExpr || ins.Op == types.OpTimerEnd) && ins.Value != "" {
				if !reads[ins.Value] {
					tips = append(tips, fmt.Sprintf("Removed unused assignment to variable '%s'", ins.Value))
					continue
				}
			}
			out = append(out, ins)
		}
		return out
	}
	script.Main = sweep(script.Main)
	for name, f := range script.Functions {
		script.Functions[name] = sweep(f)
	}
	return tips
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
				tips = append(tips, fmt.Sprintf("Merged %d consecutive PRINT statements into a single buffer operation", merged+1))
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
