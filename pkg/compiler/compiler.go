package compiler

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"sharkscript/pkg/types"
)

func Compile(srcPath string, noOptimize bool) error {
	fmt.Printf("Initializing Build: %s\n", srcPath)

	script, lineNum, tips, err := Parse(srcPath, noOptimize)
	if err != nil {
		return err
	}

	destPath := strings.TrimSuffix(srcPath, ".shark") + ".shx"
	dest, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer dest.Close()

	dest.Write([]byte("SHARK01"))
	encoder := gob.NewEncoder(dest)
	if err := encoder.Encode(script); err != nil {
		return fmt.Errorf("failed to encode bytecode: %w", err)
	}

	fmt.Printf("[SUCCESS] Bytecode Exported: %s\n", destPath)
	if !noOptimize {
		script.Main = optimizePeephole(script.Main)
		script.Main = unrollLoops(script.Main)
		if lineNum > 2000 {
			fmt.Printf("[SYSTEM] Large source detected (%d lines). Multi-threaded compilation active.\n", lineNum)
			var wg sync.WaitGroup
			var mu sync.Mutex

			mMain, mTips := mergePrints(script.Main)
			script.Main = mMain
			tips = append(tips, mTips...)

			for name, fn := range script.Functions {
				wg.Add(1)
				go func(n string, f []types.Instruction) {
					defer wg.Done()
					optFn, optTips := mergePrints(unrollLoops(optimizePeephole(f)))
					mu.Lock()
					script.Functions[n] = optFn
					tips = append(tips, optTips...)
					mu.Unlock()
				}(name, fn)
			}
			wg.Wait()
		} else {
			mMain, mTips := mergePrints(script.Main)
			script.Main = mMain
			tips = append(tips, mTips...)
			for name, fn := range script.Functions {
				mFn, fTips := mergePrints(unrollLoops(optimizePeephole(fn)))
				script.Functions[name] = mFn
				tips = append(tips, fTips...)
			}
		}
		optimizedTips := optimizeUnusedVariables(&script)
		tips = append(tips, optimizedTips...)
	}
	printSuccess(srcPath, destPath, lineNum, script, tips, noOptimize)
	return nil
}

func Parse(srcPath string, noOptimize bool) (types.CompiledScript, int, []string, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return types.CompiledScript{}, 0, nil, fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	fmt.Printf("[Parsing Source] - %s\n", srcPath)
	scanner := bufio.NewScanner(src)
	lineNum := 0
	tips := []string{}

	functions := make(map[string][]types.Instruction)
	imports := []string{}
	lastWasIf := false
	usesBypass := false

	type control struct {
		op   string
		val  string
		name string
	}
	stack := [][]types.Instruction{{}}
	var ctrlStack []control

	validateVar := func(name string, line int) error {
		if strings.Contains(name, "%") {
			return fmt.Errorf("line %d: invalid variable name '%s' (do not use %% in assignments/targets)", line, name)
		}
		return nil
	}

	parseLeaf := func(s string) *types.LogicExpr {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "%") && strings.HasSuffix(s, "%") {
			return &types.LogicExpr{Op: types.LogVar, Value: s[1 : len(s)-1]}
		}
		return &types.LogicExpr{Op: types.LogConst, Value: s}
	}

	var compileLogic func(string, string) *types.LogicExpr
	compileLogic = func(expr string, upperExpr string) *types.LogicExpr {
		expr = strings.TrimSpace(expr)
		if upperExpr == "" {
			upperExpr = strings.ToUpper(expr)
		}

		if idx := strings.Index(upperExpr, " OR "); idx != -1 {
			return &types.LogicExpr{Op: types.LogOr, Left: compileLogic(expr[:idx], upperExpr[:idx]), Right: compileLogic(expr[idx+4:], upperExpr[idx+4:])}
		}
		if idx := strings.Index(upperExpr, " AND "); idx != -1 {
			return &types.LogicExpr{Op: types.LogAnd, Left: compileLogic(expr[:idx], upperExpr[:idx]), Right: compileLogic(expr[idx+5:], upperExpr[idx+5:])}
		}
		if upperExpr == "MALICIOUS" {
			return &types.LogicExpr{Op: types.LogMalicious}
		}

		operators := []struct {
			token string
			op    types.LogicOp
		}{
			{" == ", types.LogEq}, {" != ", types.LogNe}, {" < ", types.LogLt}, {" > ", types.LogGt},
			{"PROTO ", types.LogProto}, {"CONTAINS ", types.LogContains},
		}
		for _, o := range operators {
			if idx := strings.Index(upperExpr, o.token); idx != -1 {
				left := strings.TrimSpace(expr[:idx])
				right := strings.TrimSpace(expr[idx+len(o.token):])
				return &types.LogicExpr{Op: o.op, Left: parseLeaf(left), Right: parseLeaf(right)}
			}
		}
		if strings.Contains(expr, ".") {
			return &types.LogicExpr{Op: types.LogExt, Value: expr}
		}
		return nil
	}

	var containsIter func([]types.Instruction) bool
	containsIter = func(insts []types.Instruction) bool {
		for _, ins := range insts {
			if strings.Contains(ins.Message, "%ITER%") || strings.Contains(ins.Value, "%ITER%") {
				return true
			}
			if len(ins.Body) > 0 && containsIter(ins.Body) {
				return true
			}
		}
		return false
	}

	prepare := func(ins *types.Instruction) error {
		hasVarInVal := strings.Contains(ins.Value, "%")
		hasVarInMsg := strings.Contains(ins.Message, "%")

		if !hasVarInVal && !hasVarInMsg {
			ins.IsStatic = true
			if ins.Value != "" {
				durStr := strings.ToLower(ins.Value)
				durStr = strings.ReplaceAll(durStr, "min", "m")
				if d, err := time.ParseDuration(durStr); err == nil {
					ins.Duration = d
				}
			}

			if v, err := strconv.Atoi(ins.Value); err == nil {
				ins.IntValue = v
			}
			if ins.Op == types.OpPrint || ins.Op == types.OpIfPrint || ins.Op == types.OpSystem || ins.Op == types.OpLog {
				ins.Message = convertMinecraftColors(strings.ReplaceAll(ins.Message, "\\033", "\x1b"))
			}
		}

		if hasVarInMsg {
			ins.Message = strings.ReplaceAll(ins.Message, "\\033", "\x1b")
			ins.TemplateParts = parseTemplate(ins.Message)
		}
		if hasVarInVal {
			ins.Value = strings.ReplaceAll(ins.Value, "\\033", "\x1b")
		}

		if ins.Op == types.OpWhile || (ins.Op >= types.OpIfPrint && ins.Op <= types.OpIfBreak) || ins.Op == types.OpIfComplex {
			ins.Condition = compileLogic(ins.Value, "")
			if ins.Condition == nil {
				return fmt.Errorf("invalid condition expression: '%s'", ins.Value)
			}
		}

		if !noOptimize && ins.Op == types.OpSetExpr && ins.IsStatic {
			ins.Message = evalMath(ins.Message)
			ins.Op = types.OpSet
		}

		return nil
	}

	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()
		if len(rawLine) == 0 {
			continue
		}
		line := strings.TrimSpace(rawLine)
		if line == "" || line[0] == '#' || strings.HasPrefix(line, "//") {
			continue
		}
		if !usesBypass && strings.Contains(line, "%BYPASS_TIME%") {
			usesBypass = true
		}
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		cmd := strings.ToUpper(parts[0])

		if cmd == "LOOP" {
			if len(parts) < 2 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: LOOP requires a count", lineNum)
			}
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "LOOP", val: parts[1]})
			continue
		}

		if cmd == "PARALLEL" && len(parts) > 1 && strings.ToUpper(parts[1]) == "LOOP" {
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: PARALLEL LOOP requires a count", lineNum)
			}
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "PARALLEL_LOOP", val: parts[2]})
			continue
		}

		if cmd == "ENDLOOP" {
			if len(ctrlStack) == 0 || (ctrlStack[len(ctrlStack)-1].op != "LOOP" && ctrlStack[len(ctrlStack)-1].op != "PARALLEL_LOOP") {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: ENDLOOP without LOOP", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			op := types.OpLoop
			if ctrl.op == "PARALLEL_LOOP" {
				op = types.OpParallelLoop
				if len(body) == 0 {
					op = types.OpEmptyParallelLoop
				}
			}

			if !noOptimize && op == types.OpLoop && ctrl.val != "" {
				if count, err := strconv.Atoi(ctrl.val); err == nil && count >= 10000 {
					op = types.OpParallelLoop
					tips = append(tips, fmt.Sprintf("Line %d: Automatically parallelized large loop (%s iterations)", lineNum, ctrl.val))
				}
			}

			if !noOptimize && op == types.OpParallelLoop && ctrl.val != "" {
				if count, err := strconv.Atoi(ctrl.val); err == nil && count > 0 && count < 128 {
					op = types.OpLoop
					tips = append(tips, fmt.Sprintf("Line %d: Downgraded small parallel loop to sequential for better performance", lineNum))
				}
			}

			ins := types.Instruction{Op: op, Value: ctrl.val, Body: body, NeedsIteration: containsIter(body)}
			if !noOptimize && len(body) == 1 && body[0].Op == types.OpPrint {
				switch op {
				case types.OpLoop:
					tips = append(tips, fmt.Sprintf("Line %d: Optimized loop to high-speed single-instruction mode", lineNum))
				case types.OpParallelLoop:
					tips = append(tips, fmt.Sprintf("Line %d: Optimized parallel loop to high-speed buffered mode", lineNum))
				}
				ins.IsSinglePrintLoop = true
			}
			if err := prepare(&ins); err != nil {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: %v", lineNum, err)
			}
			stack[len(stack)-1] = append(stack[len(stack)-1], ins)
			continue
		}

		if cmd == "WHILE" {
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "WHILE", val: strings.Join(parts[1:], " ")})
			continue
		}

		if cmd == "ENDWHILE" {
			if len(ctrlStack) == 0 || ctrlStack[len(ctrlStack)-1].op != "WHILE" {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: ENDWHILE without WHILE", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			ins := types.Instruction{Op: types.OpWhile, Value: ctrl.val, Body: body}
			if err := prepare(&ins); err != nil {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: %v", lineNum, err)
			}
			stack[len(stack)-1] = append(stack[len(stack)-1], ins)
			continue
		}

		if cmd == "ENDIF" {
			if len(ctrlStack) == 0 || ctrlStack[len(ctrlStack)-1].op != "IF" {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: ENDIF without IF", lineNum)
			}

			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]

			if !noOptimize && len(body) == 0 {
				tips = append(tips, fmt.Sprintf("Line %d: Automatically removed empty IF block", lineNum))
				continue
			}

			if !noOptimize && len(body) == 1 && body[0].Op == types.OpPrint {
				pIns := body[0]
				ins := types.Instruction{Op: types.OpIfPrint, Value: ctrl.val, Message: pIns.Message}
				tips = append(tips, fmt.Sprintf("Line %d: Inlined single PRINT instruction into IF condition", lineNum))
				if err := prepare(&ins); err != nil {
					return types.CompiledScript{}, lineNum, nil, err
				}
				stack[len(stack)-1] = append(stack[len(stack)-1], ins)
				continue
			}

			ins := types.Instruction{Op: types.OpIfComplex, Value: ctrl.val, Body: body}
			if err := prepare(&ins); err != nil {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: %v", lineNum, err)
			}
			stack[len(stack)-1] = append(stack[len(stack)-1], ins)
			continue
		}

		if cmd == "FUNCTION" {
			if len(parts) < 2 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: FUNCTION requires a name", lineNum)
			}
			if _, exists := functions[parts[1]]; exists {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: redeclaration of function '%s'", lineNum, parts[1])
			}
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "FUNCTION", name: parts[1]})
			continue
		}

		if cmd == "ENDFUNCTION" {
			if len(ctrlStack) == 0 || ctrlStack[len(ctrlStack)-1].op != "FUNCTION" {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: ENDFUNCTION without FUNCTION", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			functions[ctrl.name] = body
			continue
		}

		var ins types.Instruction
		currentIsIf := false
		switch cmd {
		case "USE":
			path := strings.TrimSuffix(parts[1], ";")
			imports = append(imports, path)
			ins.Op = types.OpUse
			ins.Value = path
		case "TIMER_START":
			ins.Op = types.OpTimerStart
			if len(parts) > 1 {
				ins.Value = parts[1]
			}
		case "TIMER_END":
			if len(parts) < 2 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: TIMER_END requires a target variable name", lineNum)
			}
			ins.Op, ins.Value = types.OpTimerEnd, parts[1]
		case "SET":
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: SET requires var and val", lineNum)
			}
			if err := validateVar(parts[1], lineNum); err != nil {
				return types.CompiledScript{}, lineNum, nil, err
			}
			val := strings.Join(parts[2:], " ")
			if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
				val = val[1 : len(val)-1]
			}
			if len(parts) > 2 && parts[2] == "=" {
				ins.Op = types.OpSetExpr
				ins.Value = parts[1]
				ins.Message = strings.Join(parts[3:], " ")
			} else {
				ins.Op, ins.Value, ins.Message = types.OpSet, parts[1], val
			}
		case "GET_HEADER":
			ins.Op, ins.Value, ins.Message = types.OpGetHeader, parts[1], parts[2]
		case "SET_HEADER":
			if err := validateVar(parts[1], lineNum); err != nil {
				return types.CompiledScript{}, lineNum, nil, err
			}
			ins.Op, ins.Value, ins.Message = types.OpSetHeader, parts[1], strings.Join(parts[2:], " ")
		case "TIME":
			ins.Op, ins.Value = types.OpTime, parts[1]
		case "INCREMENT":
			ins.Op, ins.Value = types.OpIncrement, parts[1]
		case "HTTP":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: HTTP requires method, URL and target_var", lineNum)
			}
			method := strings.ToUpper(parts[1])
			url, target := parts[2], parts[3]
			switch method {
			case "GET":
				ins.Op, ins.Value, ins.Message = types.OpFetch, url, target
			case "POST":
				ins.Op, ins.Value = types.OpPost, url
				uIdx := strings.Index(rawLine, url)
				tIdx := strings.Index(rawLine[uIdx+len(url):], target)
				ins.Message = target + "|" + strings.TrimSpace(rawLine[uIdx+len(url)+tIdx+len(target):])
			case "PUT", "PATCH", "DELETE":
				switch method {
				case "PUT":
					ins.Op = types.OpPut
				case "PATCH":
					ins.Op = types.OpPatch
				case "DELETE":
					ins.Op = types.OpDelete
				}
				ins.Value = url
				uIdx := strings.Index(rawLine, url)
				tIdx := strings.Index(rawLine[uIdx+len(url):], target)
				ins.Message = target + "|" + strings.TrimSpace(rawLine[uIdx+len(url)+tIdx+len(target):])
			}
		case "IF":
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: IF missing arguments", lineNum)
			}

			actionIdx := -1
			for i := 1; i < len(parts); i++ {
				p := parts[i]
				u := strings.ToUpper(p)
				if u == "PRINT" || u == "CALL" || u == "BLOCK" || u == "EXEC" || u == "HTTP" || u == "BREAK" || u == "INPUT" || u == "SEARCH" || u == "SERVE" {
					actionIdx = i
					break
				}
			}

			if actionIdx == -1 {
				ins.Value = strings.Join(parts[1:], " ")
				if ins.Value == "" {
					return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: IF block requires a condition", lineNum)
				}
				stack = append(stack, []types.Instruction{})
				ctrlStack = append(ctrlStack, control{op: "IF", val: ins.Value})
				currentIsIf = true
				lastWasIf = currentIsIf
				continue
			}

			if actionIdx == 1 {
			}

			currentIsIf = true
			ins.Value = strings.Join(parts[1:actionIdx], " ")

			if strings.ToUpper(parts[actionIdx]) == "HTTP" {
				ins.Op = types.OpIfPost
				if len(parts) > actionIdx+3 {
					ins.Message = parts[actionIdx+1] + " " + parts[actionIdx+2] + " " + strings.Join(parts[actionIdx+3:], " ")
				} else {
					return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: IF ... HTTP requires method, URL and target_var", lineNum)
				}
			} else {
				action := strings.ToUpper(parts[actionIdx])
				switch action {
				case "PRINT":
					ins.Op = types.OpIfPrint
					ins.Message = strings.Join(parts[actionIdx+1:], " ")
				case "CALL":
					ins.Op = types.OpIfCall
					ins.Message = strings.Join(parts[actionIdx+1:], " ")
				case "BLOCK":
					ins.Op = types.OpIfBlock
				case "EXEC":
					ins.Op = types.OpIfExec
					ins.Message = strings.Join(parts[actionIdx+1:], " ")
				case "BREAK":
					ins.Op = types.OpIfBreak
				case "INPUT":
					ins.Op = types.OpInput
					ins.Condition = compileLogic(ins.Value, "")
					if ins.Condition == nil {
						return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: invalid condition expression: '%s'", lineNum, ins.Value)
					}
					if len(parts) > actionIdx+2 {
						ins.Value = parts[actionIdx+1]
						ins.Message = strings.Join(parts[actionIdx+2:], " ")
					} else {
						return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: IF ... INPUT requires a target variable", lineNum)
					}
				case "SEARCH":
					ins.Op = types.OpSearch
					ins.Condition = compileLogic(ins.Value, "")
					if ins.Condition == nil {
						return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: invalid condition expression: '%s'", lineNum, ins.Value)
					}
					if len(parts) > actionIdx+3 {
						ins.Value = parts[actionIdx+2]
						ins.Message = parts[actionIdx+1] + "|" + strings.Join(parts[actionIdx+3:], " ")
					} else {
						return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: IF ... SEARCH requires path, target_var and pattern", lineNum)
					}
				case "SERVE":
					ins.Op = types.OpServe
					ins.Condition = compileLogic(ins.Value, "")
					if ins.Condition == nil {
						return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: invalid condition expression: '%s'", lineNum, ins.Value)
					}
					args := parts[actionIdx+1:]
					if len(args) < 1 {
						return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: IF ... SERVE requires a port", lineNum)
					}
					port := args[0]
					dir := ""
					if len(args) > 1 {
						if strings.ToUpper(args[len(args)-1]) == "PUBLIC" {
							port += "|PUBLIC"
							if len(args) > 2 {
								dir = args[1]
							}
						} else {
							dir = args[1]
						}
					}
					ins.Message = port + ">" + dir
				default:
					ins.Message = strings.Join(parts[actionIdx+1:], " ")
				}
			}
		case "ELSE":
			if !lastWasIf {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: ELSE must follow an IF statement", lineNum)
			}
			ins.Op = types.OpElse
			action := strings.ToUpper(parts[1])
			ins.Value = "ELSE_" + action
			ins.Message = strings.Join(parts[2:], " ")
		case "PRINT":
			ins.Op = types.OpPrint
			idx := strings.Index(strings.ToUpper(rawLine), "PRINT")
			if idx != -1 {
				ins.Message = rawLine[idx+5:]
				if len(ins.Message) > 0 && ins.Message[0] == ' ' {
					ins.Message = ins.Message[1:]
				}
			}
		case "CALL":
			ins.Op, ins.Value = types.OpCall, parts[1]
		case "SLEEP":
			ins.Op, ins.Value = types.OpSleep, parts[1]
		case "EXEC":
			idx := strings.Index(strings.ToUpper(rawLine), "EXEC")
			content := strings.TrimSpace(rawLine[idx+4:])
			if strings.HasPrefix(content, "\"") {
				endQuote := strings.LastIndex(content, "\"")
				if endQuote > 0 {
					ins.Op = types.OpExec
					ins.Message = content[1:endQuote]
					ins.Value = strings.TrimSpace(content[endQuote+1:])
				} else {
					ins.Op, ins.Message = types.OpExec, content
				}
			} else {
				ins.Op, ins.Message = types.OpExec, content
			}
		case "INPUT":
			if len(parts) >= 2 {
				if err := validateVar(parts[1], lineNum); err != nil {
					return types.CompiledScript{}, lineNum, nil, err
				}
				ins.Op = types.OpInput
				ins.Value = parts[1]
				ins.Message = strings.Join(parts[2:], " ")
			} else {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: INPUT requires a target variable", lineNum)
			}
		case "GET_ISP":
			ins.Op, ins.Value, ins.Message = types.OpGetISP, parts[1], parts[2]
		case "BLOCK":
			ins.Op = types.OpBlock
		case "SEARCH":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: SEARCH requires path, target_var and pattern", lineNum)
			}
			ins.Op = types.OpSearch
			ins.Value = parts[2]
			ins.Message = parts[1] + "|" + strings.Join(parts[3:], " ")
		case "READ_FILE":
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: READ_FILE requires path and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpReadFile, parts[1], parts[2]
		case "TOKENIZE":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: TOKENIZE requires source, delimiter, and target_array", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpTokenize, parts[1], parts[2]+"|"+parts[3]
		case "ARRAY_GET":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: ARRAY_GET requires array, index, and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpArrayGet, parts[1], parts[2]+"|"+parts[3]
		case "ARRAY_SET":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: ARRAY_SET requires array, index, and value", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpArraySet, parts[1], parts[2]+"|"+strings.Join(parts[3:], " ")
		case "ARRAY_LEN":
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: ARRAY_LEN requires array and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpArrayLen, parts[1], parts[2]
		case "INDEX_OF":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: INDEX_OF requires source, search_term, and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpIndexOf, parts[1], parts[2]+"|"+parts[3]
		case "SUBSTRING":
			if len(parts) < 5 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: SUBSTRING requires source, start, length, and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpSubstring, parts[1], parts[2]+"|"+parts[3]+"|"+parts[4]
		case "JSON_EXTRACT":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: JSON_EXTRACT requires source, key, and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpJsonExtract, parts[1], parts[2]+"|"+parts[3]
		case "SYSTEM":
			ins.Op, ins.Message = types.OpSystem, strings.Join(parts[1:], " ")
		case "SERVE":
			if len(parts) < 2 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: SERVE requires a port", lineNum)
			}
			ins.Op, ins.Value = types.OpServe, parts[1]
			if len(parts) > 2 {
				if strings.ToUpper(parts[len(parts)-1]) == "PUBLIC" {
					ins.Value += "|PUBLIC"
					if len(parts) > 3 {
						ins.Message = parts[2]
					}
				} else {
					ins.Message = parts[2]
				}
			}
		case "RAW":
			ins.Op, ins.Message = types.OpData, strings.Join(parts[1:], " ")
		case "REDIRECT":
			ins.Op, ins.Value = types.OpRedirect, parts[2]
		case "SPOOF":
			ins.Op, ins.Value = types.OpSpoof, parts[1]
		case "ALERT":
			ins.Op, ins.Message = types.OpAlert, strings.Join(parts[1:], " ")
		case "BREAK":
			ins.Op = types.OpBreak
		case "DISCORD_LIMITTO_CHANNEL":
			ins.Op, ins.Value = types.OpDiscordLimit, parts[1]
		case "NUKE_CONNECTION":
			ins.Op = types.OpNuke
		case "DISCORD_CONNECT":
			ins.Op, ins.Value = types.OpDiscordConnect, parts[1]
		case "SYS_WRITE":
			ins.Op, ins.Message = types.OpSysWrite, strings.Join(parts[1:], " ")
		case "SYS_READ_FILE":
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: SYS_READ_FILE requires filename and target variable", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpSysReadFile, parts[1], parts[2]
		case "SYS_EXIT":
			ins.Op = types.OpSysExit
			if len(parts) > 1 {
				ins.Value = parts[1]
			}
		case "SYS_YIELD":
			ins.Op = types.OpSysYield
		case "BashKILL_PID":
			ins.Op = types.OpBashKill
		default:
			if strings.HasPrefix(parts[0], "%") && len(parts) >= 3 && parts[1] == "=" {
				varName := strings.Trim(parts[0], "%")
				if err := validateVar(varName, lineNum); err != nil {
					return types.CompiledScript{}, lineNum, nil, err
				}
				ins.Op = types.OpSetExpr
				ins.Value = varName
				ins.Message = strings.Join(parts[2:], " ")
			} else {
				return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: unknown command '%s'", lineNum, cmd)
			}
		}

		lastWasIf = currentIsIf
		if err := prepare(&ins); err != nil {
			return types.CompiledScript{}, lineNum, nil, fmt.Errorf("line %d: %v", lineNum, err)
		}
		stack[len(stack)-1] = append(stack[len(stack)-1], ins)
	}

	if err := scanner.Err(); err != nil {
		return types.CompiledScript{}, lineNum, nil, fmt.Errorf("failed reading source: %w", err)
	}

	if len(ctrlStack) > 0 {
		last := ctrlStack[len(ctrlStack)-1]
		return types.CompiledScript{}, lineNum, nil, fmt.Errorf("syntax error: unclosed block type '%s' (name: %s, val: %s)", last.op, last.name, last.val)
	}

	script := types.CompiledScript{
		Main:           stack[0],
		Functions:      functions,
		Imports:        imports,
		UsesBypassTime: usesBypass,
	}

	return script, lineNum, tips, nil
}

func printSuccess(_, destPath string, lineNum int, script types.CompiledScript, tips []string, noOptimize bool) {
	totalInstructions := len(script.Main)
	for _, fn := range script.Functions {
		totalInstructions += len(fn)
	}
	fmt.Printf("\n[BUILD SUMMARY]\n")
	fmt.Printf("  Target:     %s\n", destPath)
	fmt.Printf("  Binary:     %d lines -> %d opcodes\n", lineNum, totalInstructions)
	fmt.Printf("  Functions:  %d local definitions\n", len(script.Functions))
	if noOptimize {
		fmt.Printf("  Optimizations: Disabled [-fo flag active]\n")
	} else {
		fmt.Printf("  Optimizations: Enabled [AOT, Loop-Parallelization, Block-Inlining, Static-Math]\n")
	}
	fmt.Printf("  Engine:     SHARK01 [MAXIMUM PERFORMANCE]\n")

	if len(tips) > 0 {
		fmt.Printf("\n[OPTIMIZATIONS APPLIED]\n")
		for _, tip := range tips {
			fmt.Printf("  * %s\n", tip)
		}
	}
	fmt.Printf("-----------------------------------------\n\n")
}

func CompileAOT(srcPath string, targetOS string, noOptimize bool) error {
	script, lineNum, tips, err := Parse(srcPath, noOptimize)
	if err != nil {
		return err
	}

	goCode := GenerateGo(script)

	tmpDir, _ := os.MkdirTemp("", "shark_aot_*")
	tmpFile := filepath.Join(tmpDir, "main.go")
	os.WriteFile(tmpFile, []byte(goCode), 0644)
	defer os.RemoveAll(tmpDir)

	outputBin := strings.TrimSuffix(srcPath, ".shark")
	if strings.Contains(srcPath, "/") {
		outputBin = filepath.Base(outputBin)
	}
	if targetOS == "windows" && !strings.HasSuffix(outputBin, ".exe") {
		outputBin += ".exe"
	}

	fmt.Println("[Invoking Native Toolchain] - SharkScript AOTV2")
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outputBin, tmpFile)
	cmd.Env = append(os.Environ(), "GOOS="+targetOS)

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("AOT Build Failed: %s\n%s", err, string(out))
	}

	if !noOptimize {
		if lineNum > 2000 {
			fmt.Printf("[SYSTEM] Large source detected (%d lines). Multi-threaded AOT optimization active.\n", lineNum)
			var wg sync.WaitGroup
			var mu sync.Mutex

			mMain, mTips := mergePrints(script.Main)
			script.Main = mMain
			tips = append(tips, mTips...)

			for name, fn := range script.Functions {
				wg.Add(1)
				go func(n string, f []types.Instruction) {
					defer wg.Done()
					optFn, optTips := mergePrints(unrollLoops(optimizePeephole(f)))
					mu.Lock()
					script.Functions[n] = optFn
					tips = append(tips, optTips...)
					mu.Unlock()
				}(name, fn)
			}
			wg.Wait()
		} else {
			mMain, mTips := mergePrints(script.Main)
			script.Main = mMain
			tips = append(tips, mTips...)
			for name, fn := range script.Functions {
				mFn, fTips := mergePrints(unrollLoops(optimizePeephole(fn)))
				script.Functions[name] = mFn
				tips = append(tips, fTips...)
			}
		}
		optimizedTips := optimizeUnusedVariables(&script)
		tips = append(tips, optimizedTips...)
	}

	printSuccess(srcPath, outputBin+" (NATIVE)", lineNum, script, tips, noOptimize)
	return nil
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
func GenerateGo(script types.CompiledScript) string {
	required := map[string]bool{
		"sharkscript/pkg/types":        true,
		"bufio":                        true,
		"time":                         true,
		"os":                           true,
		"strings":                      false,
		"strconv":                      false,
		"fmt":                          false,
		"os/exec":                      false,
		"net/http":                     false,
		"github.com/gorilla/websocket": false,
		"encoding/json":                false,
		"io":                           false,
		"sync":                         false,
		"bytes":                        false,
		"runtime":                      false,
	}

	needsEvalMath := false
	needsExpandVars := false

	var analyze func([]types.Instruction)
	analyze = func(insts []types.Instruction) {
		for _, ins := range insts {
			if strings.Contains(ins.Message, "%") || strings.Contains(ins.Value, "%") || strings.Contains(ins.Message, "&") || strings.Contains(ins.Value, "&") {
				needsExpandVars = true
				required["strings"] = true
				required["strconv"] = true
			}
			switch ins.Op {
			case types.OpInput:
				required["fmt"] = true
				required["bufio"] = true
				required["strings"] = true
				needsExpandVars = true
			case types.OpSet, types.OpSetExpr:
				if ins.Op == types.OpSetExpr {
					required["strings"] = true
					required["strconv"] = true
					needsEvalMath = true
				}
			case types.OpExec:
				required["os/exec"] = true
				required["strings"] = true
				needsExpandVars = true
			case types.OpIncrement:
				required["strconv"] = true
			case types.OpParallelLoop:
				required["sync"] = true
				required["runtime"] = true
				required["bytes"] = true
				if !ins.IsStatic || ins.IsSinglePrintLoop {
					required["strconv"] = true
				}
			case types.OpEmptyParallelLoop:
				required["time"] = true
				required["strconv"] = true
			case types.OpLoop:
				if !ins.IsStatic {
					required["strconv"] = true
				}
			case types.OpTime, types.OpTimerStart, types.OpTimerEnd:
				required["time"] = true
				required["strconv"] = true
			case types.OpReadFile:
				required["os"] = true
				needsExpandVars = true
			case types.OpServe:
				required["net/http"] = true
				required["strings"] = true
				required["fmt"] = true
				needsExpandVars = true
			case types.OpFetch, types.OpPost, types.OpPut, types.OpPatch, types.OpDelete:
				required["net/http"] = true
				required["io"] = true
				required["strings"] = true
				needsExpandVars = true
			case types.OpJsonExtract:
				required["encoding/json"] = true
				required["fmt"] = true
				needsExpandVars = true
			case types.OpDiscordConnect:
				required["github.com/gorilla/websocket"] = true
				required["encoding/json"] = true
				required["net/http"] = true
				needsExpandVars = true
			case types.OpSetHeader:
				needsExpandVars = true
			case types.OpSubstring:
				needsExpandVars = true
			case types.OpSleep:
				required["time"] = true
				required["strconv"] = true
				needsExpandVars = true
			case types.OpSysWrite, types.OpSysReadFile, types.OpSysExit, types.OpSysYield:
				required["syscall"] = true
				required["unsafe"] = true
				required["runtime"] = true
			}
			if len(ins.Body) > 0 {
				analyze(ins.Body)
			}
		}
	}

	regMap := make(map[string]int)
	getRegID := func(name string) int {
		if id, ok := regMap[name]; ok {
			return id
		}
		id := len(regMap)
		regMap[name] = id
		return id
	}

	var collectVars func([]types.Instruction)
	collectVars = func(insts []types.Instruction) {
		for _, ins := range insts {
			if ins.Op == types.OpEmptyParallelLoop || ins.Op == types.OpMathLoop {
				getRegID("BYPASS_TIME")
			}
			if ins.Value != "" && (ins.Op == types.OpSet || ins.Op == types.OpSetExpr || ins.Op == types.OpIncrement || ins.Op == types.OpTimerEnd || ins.Op == types.OpInput || ins.Op == types.OpFetch || ins.Op == types.OpPost || ins.Op == types.OpPut || ins.Op == types.OpPatch || ins.Op == types.OpDelete || ins.Op == types.OpJsonExtract || ins.Op == types.OpReadFile || ins.Op == types.OpSubstring || ins.Op == types.OpArrayGet || ins.Op == types.OpArrayLen || ins.Op == types.OpIndexOf) {
				getRegID(ins.Value)
			}
			if strings.Contains(ins.Message, "%") {
				parts := parseTemplate(ins.Message)
				for i := 1; i < len(parts); i += 2 {
					if parts[i] != "ITER" && parts[i] != "CORE" && parts[i] != "SRC_IP" && parts[i] != "DST_IP" && parts[i] != "PROTO" && parts[i] != "PROCESS" && parts[i] != "PID" {
						getRegID(parts[i])
					}
				}
			}
			if strings.Contains(ins.Value, "%") {
				parts := parseTemplate(ins.Value)
				for i := 1; i < len(parts); i += 2 {
					if parts[i] != "ITER" && parts[i] != "CORE" && parts[i] != "SRC_IP" && parts[i] != "DST_IP" && parts[i] != "PROTO" && parts[i] != "PROCESS" && parts[i] != "PID" {
						getRegID(parts[i])
					}
				}
			}
			if ins.Condition != nil {
				var walk func(*types.LogicExpr)
				walk = func(e *types.LogicExpr) {
					if e == nil {
						return
					}
					if e.Op == types.LogVar {
						getRegID(e.Value)
					}
					walk(e.Left)
					walk(e.Right)
				}
				walk(ins.Condition)
			}
			if len(ins.Body) > 0 {
				collectVars(ins.Body)
			}
		}
	}

	analyze(script.Main)
	for _, fn := range script.Functions {
		analyze(fn)
	}
	collectVars(script.Main)
	for _, fn := range script.Functions {
		collectVars(fn)
	}

	var sb strings.Builder
	sb.WriteString("package main\n\nimport (\n")
	for pkg, req := range required {
		if req {
			fmt.Fprintf(&sb, "\t\"%s\"\n", pkg)
		}
	}
	sb.WriteString(")\n\n")

	sb.WriteString("var discordLimitChannel string\n")
	sb.WriteString("var regMap = map[string]int{\n")
	for k, v := range regMap {
		fmt.Fprintf(&sb, "\t%q: %d,\n", k, v)
	}
	sb.WriteString("}\n\n")

	if required["sync"] && required["bytes"] {
		sb.WriteString("var bufferPool = sync.Pool{\n")
		sb.WriteString("\tNew: func() any { return bytes.NewBuffer(make([]byte, 5*1024*1024)) },\n}\n\n")
	}

	sb.WriteString("func main() {\n")
	sb.WriteString("\tout := bufio.NewWriterSize(os.Stdout, 5*1024*1024)\n")
	sb.WriteString("\tExecute(&types.PacketData{}, nil, make(map[string][]string), make(map[string]time.Time), make(map[string]string), out)\n")
	sb.WriteString("\tout.Flush()\n")
	if required["github.com/gorilla/websocket"] || required["net/http"] {
		sb.WriteString("\tselect{}\n")
	}
	sb.WriteString("}\n\n")

	for name, body := range script.Functions {
		fmt.Fprintf(&sb, "func %s(pkt *types.PacketData, vars []string, arrays map[string][]string, timers map[string]time.Time, headers map[string]string, out *bufio.Writer) bool {\n", name)
		for _, ins := range body {
			sb.WriteString(translateToGo(ins, 1, false, regMap))
		}
		sb.WriteString("\treturn false\n}\n\n")
	}

	sb.WriteString("func Execute(pkt *types.PacketData, _unused map[string]string, arrays map[string][]string, timers map[string]time.Time, headers map[string]string, out *bufio.Writer) bool {\n")
	fmt.Fprintf(&sb, "\tvars := make([]string, %d)\n", len(regMap)+128)
	sb.WriteString("\t_ = pkt\n")
	sb.WriteString("\t_ = vars\n")
	sb.WriteString("\t_ = arrays\n")
	sb.WriteString("\t_ = timers\n")
	sb.WriteString("\t_ = headers\n")
	for _, ins := range script.Main {
		sb.WriteString(translateToGo(ins, 1, false, regMap))
	}
	sb.WriteString("\treturn false\n}\n")

	if needsExpandVars {
		sb.WriteString(`
func convertMinecraftColors(input string) string {
	if !strings.Contains(input, "&") { return input }
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

func expandVars(input string, vars []string, pkt *types.PacketData) string {
	if !strings.Contains(input, "%") { return convertMinecraftColors(input) }
	var sb strings.Builder
	curr := input
	for {
		idx := strings.IndexByte(curr, '%')
		if idx == -1 { sb.WriteString(curr); break }
		sb.WriteString(curr[:idx])
		curr = curr[idx+1:]
		end := strings.IndexByte(curr, '%')
		if end == -1 { sb.WriteByte('%'); sb.WriteString(curr); break }
		key := curr[:end]

		handled := false
		if pkt != nil {
			switch key {
			case "ITER": sb.WriteString(strconv.Itoa(pkt.Iteration)); handled = true
			case "CORE": sb.WriteString(strconv.Itoa(pkt.Core)); handled = true
			case "SRC_IP": sb.WriteString(pkt.SrcIP); handled = true
			case "DST_IP": sb.WriteString(pkt.DstIP); handled = true
			case "PROTO": sb.WriteString(pkt.Protocol); handled = true
			case "PROCESS": sb.WriteString(pkt.ProcessName); handled = true
			case "PID": sb.WriteString(strconv.Itoa(int(pkt.PID))); handled = true
			}
		}

		if !handled {
			if id, ok := regMap[key]; ok {
				val := vars[id]
				f, err := strconv.ParseFloat(val, 64)
				if err == nil && f > 0 && f < 1 {
					if strings.HasPrefix(curr[end+1:], "ms") {
						if key == "BYPASS_TIME" {
							sb.WriteString(strconv.FormatFloat(f*1000000, 'f', 4, 64))
							sb.WriteString(" nanoseconds")
						} else if f < 0.001 {
							sb.WriteString(strconv.FormatFloat(f*1000000, 'f', 4, 64))
							sb.WriteString(" nanoseconds")
						} else {
							sb.WriteString(strconv.FormatFloat(f*1000, 'f', 4, 64))
							sb.WriteString(" microseconds")
						}
						curr = curr[end+3:]
						continue
					}
				}
				sb.WriteString(val)
			}
		}
		curr = curr[end+1:]
	}
	return convertMinecraftColors(sb.String())
}
`)
	}

	if needsEvalMath {
		sb.WriteString(`
func evalMath(expr string) string {
	var tokenize func(string) []string
	tokenize = func(s string) []string {
		var t []string; start := -1
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				if start != -1 { t = append(t, s[start:i]); start = -1 }; continue
			}
			if c == '+' || c == '-' || c == '*' || c == '/' || c == '%' || c == '(' || c == ')' {
				if start != -1 { t = append(t, s[start:i]) }
				t = append(t, string(c)); start = -1
			} else if start == -1 { start = i }
		}
		if start != -1 { t = append(t, s[start:]) }; return t
	}
	var solve func([]string) string
	solve = func(tokens []string) string {
		if len(tokens) == 0 { return "0" }
		hp := make([]string, 0, len(tokens))
		for i := 0; i < len(tokens); i++ {
			t := tokens[i]
			if (t == "*" || t == "/" || t == "%") && len(hp) > 0 {
				l, _ := strconv.ParseFloat(hp[len(hp)-1], 64); i++
				if i >= len(tokens) { break }; r, _ := strconv.ParseFloat(tokens[i], 64)
				var res float64
				if t == "*" { res = l * r } else if r != 0 {
					if t == "/" { res = l / r } else { res = float64(int64(l) % int64(r)) }
				}
				hp[len(hp)-1] = strconv.FormatFloat(res, 'f', 18, 64)
			} else { hp = append(hp, t) }
		}
		tot, _ := strconv.ParseFloat(hp[0], 64)
		for i := 1; i < len(hp); i += 2 {
			if i+1 >= len(hp) { break }; op := hp[i]; v, _ := strconv.ParseFloat(hp[i+1], 64)
			if op == "+" { tot += v } else { tot -= v }
		}
		return strconv.FormatFloat(tot, 'f', 18, 64)
	}
	tokens := tokenize(expr)
	for {
		o, c := -1, -1
		for i, t := range tokens { if t == "(" { o = i } else if t == ")" { c = i; break } }
		if o != -1 && c != -1 {
			sub := solve(tokens[o+1 : c]); nt := append(tokens[:o], sub)
			tokens = append(nt, tokens[c+1:]...); continue
		}
		break
	}
	return solve(tokens)
}
`)
	}

	return sb.String()
}

func generateGoLogic(expr *types.LogicExpr, regMap map[string]int) string {
	if expr == nil {
		return "false"
	}
	switch expr.Op {
	case types.LogOr:
		return "(" + generateGoLogic(expr.Left, regMap) + " || " + generateGoLogic(expr.Right, regMap) + ")"
	case types.LogAnd:
		return "(" + generateGoLogic(expr.Left, regMap) + " && " + generateGoLogic(expr.Right, regMap) + ")"
	case types.LogEq:
		return fmt.Sprintf("(%s == %s)", generateGoLogic(expr.Left, regMap), generateGoLogic(expr.Right, regMap))
	case types.LogNe:
		return fmt.Sprintf("(%s != %s)", generateGoLogic(expr.Left, regMap), generateGoLogic(expr.Right, regMap))
	case types.LogGt:
		return fmt.Sprintf("(%s > %s)", generateGoLogic(expr.Left, regMap), generateGoLogic(expr.Right, regMap))
	case types.LogLt:
		return fmt.Sprintf("(%s < %s)", generateGoLogic(expr.Left, regMap), generateGoLogic(expr.Right, regMap))
	case types.LogVar:
		return fmt.Sprintf("vars[%d]", regMap[expr.Value])
	case types.LogConst:
		return fmt.Sprintf("%q", expr.Value)
	default:
		return "false"
	}
}

func translateToGo(ins types.Instruction, depth int, inLoop bool, regMap map[string]int) string {
	indent := strings.Repeat("\t", depth)

	generateInlinedExpand := func(input string, targetWriter string) string {
		var expansion strings.Builder
		parts := parseTemplate(input)
		for i, p := range parts {
			if i%2 == 0 {
				if p != "" {
					colored := convertMinecraftColors(p)
					fmt.Fprintf(&expansion, "%s%s.WriteString(%q)\n", indent, targetWriter, colored)
				}
			} else {
				switch p {
				case "ITER":
					fmt.Fprintf(&expansion, "%s{ var b [20]byte; %s.Write(strconv.AppendInt(b[:0], int64(pkt.Iteration), 10)) }\n", indent, targetWriter)
				case "CORE":
					fmt.Fprintf(&expansion, "%s{ var b [20]byte; %s.Write(strconv.AppendInt(b[:0], int64(pkt.Core), 10)) }\n", indent, targetWriter)
				default:
					fmt.Fprintf(&expansion, "%sif v := vars[%d]; v != \"\" { %s.WriteString(convertMinecraftColors(v)) }\n", indent, regMap[p], targetWriter)
				}
			}
		}
		return expansion.String()
	}
	switch ins.Op {
	case types.OpLoop:
		res := fmt.Sprintf("%s{\n", indent)
		if ins.IsStatic {
			res += fmt.Sprintf("%s\tfor i := 0; i < %d; i++ {\n", indent, ins.IntValue)
		} else {
			res += fmt.Sprintf("%s\tcount, _ := strconv.Atoi(vars[%d])\n", indent, regMap[ins.Value])
			res += fmt.Sprintf("%s\tfor i := 0; i < count; i++ {\n", indent)
		}

		res += fmt.Sprintf("%s\t\tpkt.Iteration = i\n", indent)
		if ins.IsSinglePrintLoop {
			res += generateInlinedExpand(ins.Body[0].Message, "out")
			res += fmt.Sprintf("%s\t\tout.WriteByte('\\n')\n", indent)
		} else {
			for _, bIns := range ins.Body {
				res += translateToGo(bIns, depth+2, true, regMap)
			}
		}
		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpFetch:
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\treq, _ := http.NewRequest(\"GET\", expandVars(%q, vars, pkt), nil)\n", indent, ins.Value)
		res += fmt.Sprintf("%s\tif req != nil {\n", indent)
		res += fmt.Sprintf("%s\t\tfor k, v := range headers { req.Header.Set(k, v) }\n", indent)
		res += fmt.Sprintf("%s\t\tresp, err := (&http.Client{}).Do(req)\n", indent)
		res += fmt.Sprintf("%s\tif err == nil {\n", indent)
		res += fmt.Sprintf("%s\t\t\tdefer resp.Body.Close(); b, _ := io.ReadAll(resp.Body); vars[%d] = string(b)\n", indent, regMap[ins.Message])
		res += fmt.Sprintf("%s\t\t}\n", indent)
		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpPost:
		parts := strings.SplitN(ins.Message, "|", 2)
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tpayload := expandVars(%q, vars, pkt)\n", indent, parts[1])
		res += fmt.Sprintf("%s\treq, _ := http.NewRequest(\"POST\", expandVars(%q, vars, pkt), strings.NewReader(payload))\n", indent, ins.Value)
		res += fmt.Sprintf("%s\tif req != nil {\n", indent)
		res += fmt.Sprintf("%s\t\tfor k, v := range headers { req.Header.Set(k, v) }\n", indent)
		res += fmt.Sprintf("%s\t\tresp, err := (&http.Client{}).Do(req)\n", indent)
		res += fmt.Sprintf("%s\tif err == nil {\n", indent)
		res += fmt.Sprintf("%s\t\t\tdefer resp.Body.Close(); b, _ := io.ReadAll(resp.Body); vars[%d] = string(b)\n", indent, regMap[parts[0]])
		res += fmt.Sprintf("%s\t\t}\n", indent)
		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpPut, types.OpPatch, types.OpDelete:
		method := "PUT"
		if ins.Op == types.OpPatch {
			method = "PATCH"
		}
		if ins.Op == types.OpDelete {
			method = "DELETE"
		}
		res := fmt.Sprintf("%s{\n", indent)
		target := ins.Message
		payload := ""
		if strings.Contains(ins.Message, "|") {
			mParts := strings.SplitN(ins.Message, "|", 2)
			target = mParts[0]
			payload = mParts[1]
		}
		res += fmt.Sprintf("%s\treq, _ := http.NewRequest(%q, expandVars(%q, vars, pkt), strings.NewReader(expandVars(%q, vars, pkt)))\n", indent, method, ins.Value, payload)
		res += fmt.Sprintf("%s\tif req != nil {\n", indent)
		res += fmt.Sprintf("%s\t\tfor k, v := range headers { req.Header.Set(k, v) }\n", indent)
		res += fmt.Sprintf("%s\t\tresp, err := (&http.Client{}).Do(req)\n", indent)
		res += fmt.Sprintf("%s\tif err == nil {\n", indent)
		res += fmt.Sprintf("%s\t\t\tdefer resp.Body.Close(); b, _ := io.ReadAll(resp.Body); vars[%d] = string(b)\n", indent, regMap[target])
		res += fmt.Sprintf("%s\t\t}\n", indent)
		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpJsonExtract:
		parts := strings.SplitN(ins.Message, "|", 2)
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tvar data any\n", indent)
		res += fmt.Sprintf("%s\tkey := strings.Trim(expandVars(%q, vars, pkt), \"\\\"\")\n", indent, parts[0])
		res += fmt.Sprintf("%s\tif err := json.Unmarshal([]byte(expandVars(%q, vars, pkt)), &data); err == nil {\n", indent, ins.Value)
		res += fmt.Sprintf("%s\t\tif arr, ok := data.([]any); ok && len(arr) > 0 { data = arr[0] }\n", indent)
		res += fmt.Sprintf("%s\t\tif m, ok := data.(map[string]any); ok {\n", indent)
		res += fmt.Sprintf("%s\t\t\tif v, exists := m[key]; exists { vars[%d] = fmt.Sprint(v) }\n", indent, regMap[parts[1]])
		res += fmt.Sprintf("%s\t\t}\n", indent)
		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpDiscordConnect:
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\ttoken := expandVars(%q, vars, pkt)\n", indent, ins.Value)
		res += fmt.Sprintf("%s\ttype gatewayEvent struct { Op int `json:\"op\"`; T string `json:\"t\"`; D json.RawMessage `json:\"d\"` }\n", indent)
		res += fmt.Sprintf("%s\t\tgo func() {\n", indent)
		res += fmt.Sprintf("%s\t\t\tdialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}\n", indent)
		res += fmt.Sprintf("%s\t\t\tfor {\n", indent)
		res += fmt.Sprintf("%s\t\t\t\tconn, _, err := dialer.Dial(\"wss://gateway.discord.gg/?v=10&encoding=json\", nil)\n", indent)
		res += fmt.Sprintf("%s\t\t\t\tif err != nil { time.Sleep(2 * time.Second); continue }\n", indent)
		res += fmt.Sprintf("%s\t\t\t\tfor {\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\t_, msg, err := conn.ReadMessage()\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tif err != nil { conn.Close(); break }\n", indent)
		res += fmt.Sprintf("%s\t\t\t\tvar ev gatewayEvent\n", indent)
		res += fmt.Sprintf("%s\t\t\t\tjson.Unmarshal(msg, &ev)\n", indent)
		res += fmt.Sprintf("%s\t\t\t\tif ev.Op == 10 {\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tident := `{\"op\":2,\"d\":{\"token\":\"`+token+`\",\"intents\":33281,\"properties\":{\"$os\":\"linux\",\"$browser\":\"shs\",\"$device\":\"shs\"},\"presence\":{\"status\":\"online\",\"afk\":false}}}`\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tconn.WriteMessage(websocket.TextMessage, []byte(ident))\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tvar d map[string]float64; json.Unmarshal(ev.D, &d)\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\thb := d[\"heartbeat_interval\"]\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tgo func() { for { time.Sleep(time.Duration(hb)*time.Millisecond); if err := conn.WriteMessage(websocket.TextMessage, []byte(`{\"op\":1,\"d\":null}`)); err != nil { return } } }()\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t}\n", indent)
		res += fmt.Sprintf("%s\t\t\t\tif ev.T == \"MESSAGE_CREATE\" {\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tvar d map[string]any; json.Unmarshal(ev.D, &d)\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tcID, _ := d[\"channel_id\"].(string)\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tif discordLimitChannel != \"\" && cID != discordLimitChannel { continue }\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tauthor, _ := d[\"author\"].(map[string]any)\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t\tvars[%d] = \"false\"\n", indent, regMap["msg_author_bot"])
		res += fmt.Sprintf("%s\t\t\t\t\tif b, ok := author[\"bot\"].(bool); ok && b { vars[%d] = \"true\" }\n", indent, regMap["msg_author_bot"])
		res += fmt.Sprintf("%s\t\t\t\t\tvars[%d], _ = d[\"content\"].(string)\n", indent, regMap["msg_content"])
		res += fmt.Sprintf("%s\t\t\t\t\tvars[%d] = cID\n", indent, regMap["channel_id"])
		res += fmt.Sprintf("%s\t\t\t\t\tvars[%d], _ = d[\"guild_id\"].(string)\n", indent, regMap["guild_id"])
		res += fmt.Sprintf("%s\t\t\t\t\tvars[%d], _ = d[\"id\"].(string)\n", indent, regMap["msg_id"])
		res += fmt.Sprintf("%s\t\t\t\t\tON_MESSAGE(pkt, vars, arrays, timers, headers, out)\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t}\n", indent)
		res += fmt.Sprintf("%s\t\t\t\t}\n", indent)
		res += fmt.Sprintf("%s\t\t\t\ttime.Sleep(time.Second)\n", indent)
		res += fmt.Sprintf("%s\t\t\t}\n", indent)
		res += fmt.Sprintf("%s\t\t}()\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpDiscordLimit:
		return fmt.Sprintf("%sdiscordLimitChannel = expandVars(%q, vars, pkt)\n", indent, ins.Value)
	case types.OpSubstring:
		parts := strings.SplitN(ins.Message, "|", 3)
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tsrc := expandVars(%q, vars, pkt)\n", indent, ins.Value)
		res += fmt.Sprintf("%s\tstart, _ := strconv.Atoi(expandVars(%q, vars, pkt))\n", indent, parts[0])
		res += fmt.Sprintf("%s\tlength, _ := strconv.Atoi(expandVars(%q, vars, pkt))\n", indent, parts[1])
		res += fmt.Sprintf("%s\tif start >= 0 && start < len(src) {\n", indent)
		res += fmt.Sprintf("%s\t\tend := start + length\n", indent)
		res += fmt.Sprintf("%s\t\tif end > len(src) { end = len(src) }\n", indent)
		res += fmt.Sprintf("%s\t\tvars[%d] = src[start:end]\n", indent, regMap[parts[2]])
		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpSetHeader:
		return fmt.Sprintf("%sheaders[%q] = expandVars(%q, vars, pkt)\n", indent, ins.Value, ins.Message)

	case types.OpSleep:
		res := fmt.Sprintf("%sif ms, err := strconv.Atoi(expandVars(%q, vars, pkt)); err == nil {\n", indent, ins.Value)
		res += fmt.Sprintf("%s\ttime.Sleep(time.Duration(ms) * time.Millisecond)\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res

	case types.OpIfComplex:
		res := fmt.Sprintf("%sif %s {\n", indent, generateGoLogic(ins.Condition, regMap))
		for _, bIns := range ins.Body {
			res += translateToGo(bIns, depth+1, inLoop, regMap)
		}
		res += fmt.Sprintf("%s}\n", indent)
		return res

	case types.OpWhile:
		res := fmt.Sprintf("%sfor %s {\n", indent, generateGoLogic(ins.Condition, regMap))
		for _, bIns := range ins.Body {
			res += translateToGo(bIns, depth+1, true, regMap)
		}
		res += fmt.Sprintf("%s}\n", indent)
		return res

	case types.OpInput:
		res := fmt.Sprintf("%sout.Flush()\n", indent)
		res += fmt.Sprintf("%sfmt.Print(expandVars(%q, vars, pkt))\n", indent, ins.Message)
		res += fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\treader := bufio.NewReader(os.Stdin)\n", indent)
		res += fmt.Sprintf("%s\ttext, _ := reader.ReadString('\\n')\n", indent)
		res += fmt.Sprintf("%s\tvars[%d] = strings.TrimSpace(text)\n", indent, regMap[ins.Value])
		res += fmt.Sprintf("%s}\n", indent)
		return res

	case types.OpTimerStart:
		key := ins.Value
		if key == "" {
			key = "DEFAULT"
		}
		return fmt.Sprintf("%stimers[%q] = time.Now()\n", indent, key)
	case types.OpTimerEnd:
		key := ins.Value
		if key == "" {
			key = "DEFAULT"
		}
		return fmt.Sprintf("%svars[%d] = strconv.FormatFloat(time.Since(timers[%q]).Seconds(), 'f', 9, 64)\n", indent, regMap[ins.Value], key)
	case types.OpTime:
		return fmt.Sprintf("%svars[%d] = strconv.FormatFloat(float64(time.Now().UnixNano())/1e6, 'f', 9, 64)\n", indent, regMap[ins.Value])
	case types.OpExec:
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tcmd := exec.Command(\"sh\", \"-c\", expandVars(%q, vars, pkt))\n", indent, ins.Message)
		if ins.Value != "" {
			res += fmt.Sprintf("%s\tout, _ := cmd.CombinedOutput()\n", indent)
			res += fmt.Sprintf("%s\tvars[%d] = strings.TrimSpace(string(out))\n", indent, regMap[ins.Value])
		} else {
			res += fmt.Sprintf("%s\tgo cmd.Run()\n", indent)
		}
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpSet:
		if !strings.Contains(ins.Message, "%") {
			return fmt.Sprintf("%svars[%d] = %q\n", indent, regMap[ins.Value], convertMinecraftColors(ins.Message))
		}
		return fmt.Sprintf("%svars[%d] = expandVars(%q, vars, pkt)\n", indent, regMap[ins.Value], ins.Message)
	case types.OpSetExpr:
		return fmt.Sprintf("%svars[%d] = evalMath(expandVars(%q, vars, pkt))\n", indent, regMap[ins.Value], ins.Message)
	case types.OpIncrement:
		return fmt.Sprintf("%s{\n%s\tv, _ := strconv.Atoi(vars[%d])\n%s\tvars[%d] = strconv.Itoa(v + 1)\n%s}\n", indent, indent, regMap[ins.Value], indent, regMap[ins.Value], indent)
	case types.OpIfCall:
		stopCmd := "return true"
		if inLoop {
			stopCmd = "break"
		}
		return fmt.Sprintf("%sif %s { if %s(pkt, vars, arrays, timers, headers, out) { %s } }\n", indent, generateGoLogic(ins.Condition, regMap), ins.Message, stopCmd)
	case types.OpIfBreak:
		stopCmd := "return true"
		if inLoop {
			stopCmd = "break"
		}
		return fmt.Sprintf("%sif %s { %s }\n", indent, generateGoLogic(ins.Condition, regMap), stopCmd)
	case types.OpBreak:
		stopCmd := "return true"
		if inLoop {
			stopCmd = "break"
		}
		return fmt.Sprintf("%s%s\n", indent, stopCmd)
	case types.OpCall:
		stopCmd := "return true"
		if inLoop {
			stopCmd = "break"
		}
		return fmt.Sprintf("%sif %s(pkt, vars, arrays, timers, headers, out) { %s }\n", indent, ins.Value, stopCmd)
	case types.OpReadFile:
		return fmt.Sprintf("%s{ data, _ := os.ReadFile(expandVars(%q, vars, pkt)); vars[%d] = string(data) }\n", indent, ins.Value, regMap[ins.Message])
	case types.OpTokenize:
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tsrc := expandVars(%q, vars, pkt)\n", indent, ins.Value)
		res += fmt.Sprintf("%s\tmParts := strings.SplitN(%q, \"|\", 2)\n", indent, ins.Message)
		res += fmt.Sprintf("%s\tvar tokens []string\n", indent)
		res += fmt.Sprintf("%s\tswitch expandVars(mParts[0], vars, pkt) { case \"SPACE\": tokens = strings.Fields(src); case \"NEWLINE\": tokens = strings.Split(src, \"\\n\"); default: tokens = strings.Split(src, expandVars(mParts[0], vars, pkt)) }\n", indent)
		res += fmt.Sprintf("%s\tarrays[mParts[1]] = tokens\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpArrayGet:
		mParts := strings.SplitN(ins.Message, "|", 2)
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tmParts := strings.SplitN(%q, \"|\", 2)\n", indent, ins.Message)
		res += fmt.Sprintf("%s\tidx, _ := strconv.Atoi(expandVars(mParts[0], vars, pkt))\n", indent)
		res += fmt.Sprintf("%s\tif arr, ok := arrays[%q]; ok && idx >= 0 && idx < len(arr) { vars[%d] = arr[idx] }\n", indent, ins.Value, regMap[mParts[1]])
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpServe:
		res := ""
		if ins.Condition != nil {
			res += fmt.Sprintf("%sif %s {\n", indent, generateGoLogic(ins.Condition, regMap))
			indent += "\t"
		}
		portArg, dirArg := ins.Value, ins.Message
		if strings.Contains(ins.Message, ">") {
			mParts := strings.SplitN(ins.Message, ">", 2)
			portArg, dirArg = mParts[0], mParts[1]
		}
		res += fmt.Sprintf("%sgo func() {\n", indent)
		res += fmt.Sprintf("%s\trawPort := expandVars(%q, vars, pkt)\n", indent, portArg)
		res += fmt.Sprintf("%s\thost := \"127.0.0.1:\"\n", indent)
		res += fmt.Sprintf("%s\tport := rawPort\n", indent)
		res += fmt.Sprintf("%s\tif strings.HasSuffix(rawPort, \"|PUBLIC\") {\n", indent)
		res += fmt.Sprintf("%s\t\thost = \":\"\n", indent)
		res += fmt.Sprintf("%s\t\tport = strings.TrimSuffix(rawPort, \"|PUBLIC\")\n", indent)
		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s\tdir := expandVars(%q, vars, pkt)\n", indent, dirArg)
		res += fmt.Sprintf("%s\tif dir == \"\" { dir = \"./www\" }\n", indent)
		res += fmt.Sprintf("%s\tmux := http.NewServeMux()\n", indent)
		res += fmt.Sprintf("%s\tmux.Handle(\"/\", http.FileServer(http.Dir(dir)))\n", indent)
		res += fmt.Sprintf("%s\tif err := http.ListenAndServe(host+port, mux); err != nil { fmt.Printf(\"\\033[31m[SERVE ERROR]\\033[0m %%v\\n\", err) }\n", indent)
		res += fmt.Sprintf("%s}()\n", indent)
		if ins.Condition != nil {
			indent = indent[:len(indent)-1]
			res += fmt.Sprintf("%s}\n", indent)
		}
		return res
	case types.OpParallelLoop, types.OpEmptyParallelLoop:
		if ins.Op == types.OpEmptyParallelLoop {
			res := fmt.Sprintf("%s{\n", indent)
			res += fmt.Sprintf("%s\tstart := time.Now()\n", indent)
			if ins.Duration > 0 {
				res += fmt.Sprintf("%s\ttime.Sleep(time.Duration(%d))\n", indent, int64(ins.Duration))
			}
			res += fmt.Sprintf("%s\tvars[%d] = strconv.FormatFloat(float64(time.Since(start).Nanoseconds())/1e6, 'f', 9, 64)\n", indent, regMap["BYPASS_TIME"])
			res += fmt.Sprintf("%s}\n", indent)
			return res
		}
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tsnapshot := make([]string, len(vars))\n", indent)
		res += fmt.Sprintf("%s\tcopy(snapshot, vars)\n", indent)
		res += fmt.Sprintf("%s\tnumWorkers := runtime.GOMAXPROCS(0)\n", indent)
		if ins.IsStatic {
			res += fmt.Sprintf("%s\tcount := %d\n", indent, ins.IntValue)
		} else {
			res += fmt.Sprintf("%s\tcount, _ := strconv.Atoi(vars[%d])\n", indent, regMap[ins.Value])
		}

		res += fmt.Sprintf("%s\tvar wg sync.WaitGroup\n", indent)
		res += fmt.Sprintf("%s\tbuffers := make([]*bytes.Buffer, numWorkers)\n", indent)
		res += fmt.Sprintf("%s\twg.Add(numWorkers)\n", indent)
		res += fmt.Sprintf("%s\tfor w := 0; w < numWorkers; w++ {\n", indent)
		res += fmt.Sprintf("%s\t\tbuf := bufferPool.Get().(*bytes.Buffer)\n", indent)
		res += fmt.Sprintf("%s\t\tbuf.Reset()\n", indent)
		res += fmt.Sprintf("%s\t\tbuffers[w] = buf\n", indent)

		if ins.IsSinglePrintLoop {
			res += fmt.Sprintf("%s\t\tgo func(id int, lb *bytes.Buffer) {\n", indent)
			res += fmt.Sprintf("%s\t\t\tdefer wg.Done()\n", indent)
			res += fmt.Sprintf("%s\t\t\tlp := *pkt; lp.Core = id + 1\n", indent)
			res += fmt.Sprintf("%s\t\t\tvars := make([]string, len(snapshot)); copy(vars, snapshot)\n", indent)
			res += fmt.Sprintf("%s\t\t\tfor i := (count * id) / numWorkers; i < (count * (id + 1)) / numWorkers; i++ {\n", indent)
			res += fmt.Sprintf("%s\t\t\t\tlp.Iteration = i\n", indent)
			res += generateInlinedExpand(ins.Body[0].Message, "lb")
			res += fmt.Sprintf("%s\t\t\t\tlb.WriteByte('\\n')\n", indent)
			res += fmt.Sprintf("%s\t\t\t}\n", indent)
			res += fmt.Sprintf("%s\t\t}(w, buffers[w])\n", indent)
		} else {
			res += fmt.Sprintf("%s\t\tgo func(workerID int, localBuf *bytes.Buffer) {\n", indent)
			res += fmt.Sprintf("%s\t\t\tdefer wg.Done()\n", indent)
			res += fmt.Sprintf("%s\t\t\tlp := *pkt; lp.Core = workerID + 1\n", indent)
			res += fmt.Sprintf("%s\t\t\tlocalOut := bufio.NewWriterSize(localBuf, 5*1024*1024)\n", indent)
			res += fmt.Sprintf("%s\t\t\tvars := make([]string, len(snapshot)); copy(vars, snapshot)\n", indent)
			res += fmt.Sprintf("%s\t\t\t_ = vars\n", indent)
			res += fmt.Sprintf("%s\t\t\tfor i := (count * workerID) / numWorkers; i < (count * (workerID + 1)) / numWorkers; i++ {\n", indent)
			res += fmt.Sprintf("%s\t\t\t\tlp.Iteration = i\n", indent)
			for _, bIns := range ins.Body {
				res += strings.ReplaceAll(translateToGo(bIns, depth+4, true, regMap), "out.", "localOut.")
			}
			res += fmt.Sprintf("%s\t\t\t}\n", indent)
			res += fmt.Sprintf("%s\t\t\tlocalOut.Flush()\n", indent)
			res += fmt.Sprintf("%s\t\t}(w, buffers[w])\n", indent)
		}

		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s\twg.Wait()\n", indent)
		res += fmt.Sprintf("%s\tfor _, b := range buffers { out.Write(b.Bytes()); bufferPool.Put(b) }\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpMathLoop:
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tstart := time.Now()\n", indent)
		res += fmt.Sprintf("%s\titerations := %d\n", indent, ins.IntValue)
		res += fmt.Sprintf("%s\tregID := %d\n", indent, regMap[ins.Value])
		res += fmt.Sprintf("%s\tx, _ := strconv.ParseInt(vars[regID], 10, 64)\n", indent)

		var a, b, m int64 = 1, 0, 1
		parts := strings.Fields(strings.ReplaceAll(strings.ReplaceAll(ins.Message, "(", " "), ")", " "))
		if len(parts) >= 7 {
			a, _ = strconv.ParseInt(parts[2], 10, 64)
			b, _ = strconv.ParseInt(parts[4], 10, 64)
			m, _ = strconv.ParseInt(parts[6], 10, 64)
		}

		res += fmt.Sprintf("%s\tpowMod := func(a, b, m int64) int64 {\n", indent)
		res += fmt.Sprintf("%s\t\tres := int64(1); a %%= m\n", indent)
		res += fmt.Sprintf("%s\t\tfor b > 0 { if b%%2 == 1 { res = (res * a) %% m }; a = (a * a) %% m; b /= 2 }\n", indent)
		res += fmt.Sprintf("%s\t\treturn res\n\t}\n", indent)

		res += fmt.Sprintf("%s\tvar sumPowMod func(int64, int64, int64) int64\n", indent)
		res += fmt.Sprintf("%s\tsumPowMod = func(a, k, m int64) int64 {\n", indent)
		res += fmt.Sprintf("%s\t\tif k == 0 { return 0 }; if k == 1 { return 1 }\n", indent)
		res += fmt.Sprintf("%s\t\tif k%%2 == 0 { return (sumPowMod(a, k/2, m) * (1 + powMod(a, k/2, m))) %% m }\n", indent)
		res += fmt.Sprintf("%s\t\treturn (1 + a*sumPowMod(a, k-1, m)) %% m\n\t}\n", indent)

		res += fmt.Sprintf("%s\tx = (powMod(%d, int64(iterations), %d)*x + %d*sumPowMod(%d, int64(iterations), %d)) %% %d\n", indent, a, m, b, a, m, m)
		res += fmt.Sprintf("%s\tvars[regID] = strconv.FormatInt(x, 10)\n", indent)
		res += fmt.Sprintf("%s\tdur := time.Since(start)\n", indent)
		res += fmt.Sprintf("%s\tvars[regMap[\"BYPASS_TIME\"]] = strconv.FormatFloat(float64(dur.Nanoseconds())/1e6, 'f', 9, 64)\n", indent)
		res += fmt.Sprintf("%s\tout.WriteString(\"[AOT MATH OPTIMIZER] \")\n", indent)
		res += fmt.Sprintf("%s\tout.WriteString(strconv.Itoa(iterations) + \" iterations processed in \" + dur.String() + \"\\n\")\n", indent)
		res += fmt.Sprintf("%s\tout.Flush()\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res

	case types.OpPrint:
		if ins.IsStatic {
			msg := convertMinecraftColors(ins.Message) + "\n"
			return fmt.Sprintf("%sout.WriteString(%q)\n", indent, msg)
		}
		return generateInlinedExpand(ins.Message, "out") + fmt.Sprintf("%s\tout.WriteByte('\\n')\n", indent)
	case types.OpSysWrite:
		res := fmt.Sprintf("%sif runtime.GOOS != \"linux\" && runtime.GOOS != \"windows\" {\n", indent)
		res += fmt.Sprintf("%s\tmsg := expandVars(%q, vars, pkt)\n", indent, ins.Message)
		res += fmt.Sprintf("%s\tsyscall.RawSyscall(4, 1, uintptr(unsafe.Pointer(unsafe.StringData(msg))), uintptr(len(msg)))\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpSysReadFile:
		res := fmt.Sprintf("%sif runtime.GOOS != \"linux\" && runtime.GOOS != \"windows\" {\n", indent)
		res += fmt.Sprintf("%s\tname := expandVars(%q, vars, pkt)\n", indent, ins.Value)
		res += fmt.Sprintf("%s\tbuf := make([]byte, 4096)\n", indent)
		res += fmt.Sprintf("%s\tret, _, _ := syscall.RawSyscall(3, uintptr(unsafe.Pointer(unsafe.StringData(name))), uintptr(unsafe.Pointer(&buf[0])), 0)\n", indent)
		res += fmt.Sprintf("%s\tif int(ret) >= 0 { vars[%d] = string(buf[:ret]) }\n", indent, regMap[ins.Message])
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpSysExit:
		res := fmt.Sprintf("%sif runtime.GOOS != \"linux\" && runtime.GOOS != \"windows\" {\n", indent)
		res += fmt.Sprintf("%s\tcode, _ := strconv.Atoi(expandVars(%q, vars, pkt))\n", indent, ins.Value)
		res += fmt.Sprintf("%s\tsyscall.RawSyscall(1, uintptr(code), 0, 0)\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpSysYield:
		res := fmt.Sprintf("%sif runtime.GOOS != \"linux\" && runtime.GOOS != \"windows\" {\n", indent)
		res += fmt.Sprintf("%s\tsyscall.RawSyscall(24, 0, 0, 0)\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	default:
		return fmt.Sprintf("%s// Unsupported Op: %d\n", indent, ins.Op)
	}
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

func parseTemplate(input string) []string {
	pctCount := strings.Count(input, "%")
	if pctCount == 0 {
		return []string{convertMinecraftColors(input)}
	}
	parts := make([]string, 0, (pctCount/2)*2+1)
	curr := input
	for {
		idx := strings.IndexByte(curr, '%')
		if idx == -1 {
			parts = append(parts, convertMinecraftColors(curr))
			break
		}
		parts = append(parts, convertMinecraftColors(curr[:idx]))
		curr = curr[idx+1:]
		end := strings.IndexByte(curr, '%')
		if end == -1 {
			parts = append(parts, convertMinecraftColors("%"+curr))
			break
		}
		parts = append(parts, curr[:end])
		curr = curr[end+1:]
	}
	return parts
}

func evalMath(expr string) string {
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
