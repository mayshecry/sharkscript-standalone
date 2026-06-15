package compiler

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"sharkscript/pkg/types"
)

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
