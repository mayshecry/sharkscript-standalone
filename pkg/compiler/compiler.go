package compiler

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"sharkscript/pkg/types"
)

func Compile(srcPath string) error {
	fmt.Println("[Initializing Compiler] - SharkScript")
	time.Sleep(800 * time.Millisecond)

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	fmt.Printf("[Parsing Source] - %s\n", srcPath)
	scanner := bufio.NewScanner(src)
	lineNum := 0

	functions := make(map[string][]types.Instruction)
	imports := []string{}
	lastWasIf := false

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

	var compileLogic func(string) *types.LogicExpr
	compileLogic = func(expr string) *types.LogicExpr {
		expr = strings.TrimSpace(expr)
		if strings.Contains(expr, " OR ") {
			parts := strings.SplitN(expr, " OR ", 2)
			return &types.LogicExpr{Op: types.LogOr, Left: compileLogic(parts[0]), Right: compileLogic(parts[1])}
		}
		if strings.Contains(expr, " AND ") {
			parts := strings.SplitN(expr, " AND ", 2)
			return &types.LogicExpr{Op: types.LogAnd, Left: compileLogic(parts[0]), Right: compileLogic(parts[1])}
		}
		if strings.EqualFold(expr, "MALICIOUS") {
			return &types.LogicExpr{Op: types.LogMalicious}
		}
		operators := []struct {
			token string
			op    types.LogicOp
		}{
			{" < ", types.LogLt}, {" > ", types.LogGt}, {" == ", types.LogEq},
			{"PROTO ", types.LogProto}, {"CONTAINS ", types.LogContains},
		}
		for _, o := range operators {
			if idx := strings.Index(strings.ToUpper(expr), o.token); idx != -1 {
				left := strings.TrimSpace(expr[:idx])
				right := strings.TrimSpace(expr[idx+len(o.token):])
				parseLeaf := func(s string) *types.LogicExpr {
					s = strings.TrimSpace(s)
					if strings.HasPrefix(s, "%") && strings.HasSuffix(s, "%") {
						return &types.LogicExpr{Op: types.LogVar, Value: s[1 : len(s)-1]}
					}
					return &types.LogicExpr{Op: types.LogConst, Value: s}
				}
				return &types.LogicExpr{Op: o.op, Left: parseLeaf(left), Right: parseLeaf(right)}
			}
		}
		if strings.Contains(expr, ".") {
			return &types.LogicExpr{Op: types.LogExt, Value: expr}
		}
		return nil
	}

	prepare := func(ins *types.Instruction) error {
		if !strings.Contains(ins.Value, "%") && !strings.Contains(ins.Message, "%") {
			ins.IsStatic = true

			durStr := strings.ToLower(ins.Value)
			durStr = strings.ReplaceAll(durStr, "min", "m")
			if d, err := time.ParseDuration(durStr); err == nil {
				ins.Duration = d
			}

			if v, err := strconv.Atoi(ins.Value); err == nil {
				ins.IntValue = v
			}
		}
		if ins.Op == types.OpWhile || (ins.Op >= types.OpIfPrint && ins.Op <= types.OpIfBreak) {
			ins.Condition = compileLogic(ins.Value)
			if ins.Condition == nil {
				return fmt.Errorf("invalid condition expression: '%s'", ins.Value)
			}
		}
		return nil
	}

	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		cmd := strings.ToUpper(parts[0])

		if cmd == "LOOP" {
			if len(parts) < 2 {
				return fmt.Errorf("line %d: LOOP requires a count", lineNum)
			}
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "LOOP", val: parts[1]})
			continue
		}

		if cmd == "PARALLEL" && len(parts) > 1 && strings.ToUpper(parts[1]) == "LOOP" {
			if len(parts) < 3 {
				return fmt.Errorf("line %d: PARALLEL LOOP requires a count", lineNum)
			}
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "PARALLEL_LOOP", val: parts[2]})
			continue
		}

		if cmd == "ENDLOOP" {
			if len(ctrlStack) == 0 || (ctrlStack[len(ctrlStack)-1].op != "LOOP" && ctrlStack[len(ctrlStack)-1].op != "PARALLEL_LOOP") {
				return fmt.Errorf("line %d: ENDLOOP without LOOP", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			op := types.OpLoop
			if ctrl.op == "PARALLEL_LOOP" {
				op = types.OpParallelLoop
			}
			ins := types.Instruction{Op: op, Value: ctrl.val, Body: body}
			if err := prepare(&ins); err != nil {
				return fmt.Errorf("line %d: %v", lineNum, err)
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
				return fmt.Errorf("line %d: ENDWHILE without WHILE", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			ins := types.Instruction{Op: types.OpWhile, Value: ctrl.val, Body: body}
			if err := prepare(&ins); err != nil {
				return fmt.Errorf("line %d: %v", lineNum, err)
			}
			stack[len(stack)-1] = append(stack[len(stack)-1], ins)
			continue
		}

		if cmd == "FUNCTION" {
			if len(parts) < 2 {
				return fmt.Errorf("line %d: FUNCTION requires a name", lineNum)
			}
			if _, exists := functions[parts[1]]; exists {
				return fmt.Errorf("line %d: redeclaration of function '%s'", lineNum, parts[1])
			}
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "FUNCTION", name: parts[1]})
			continue
		}

		if cmd == "ENDFUNCTION" {
			if len(ctrlStack) == 0 || ctrlStack[len(ctrlStack)-1].op != "FUNCTION" {
				return fmt.Errorf("line %d: ENDFUNCTION without FUNCTION", lineNum)
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
		case "TIMER_END":
			ins.Op, ins.Value = types.OpTimerEnd, parts[1]
		case "SET":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: SET requires var and val", lineNum)
			}
			if err := validateVar(parts[1], lineNum); err != nil {
				return err
			}
			if parts[2] == "=" {
				ins.Op = types.OpSetExpr
				ins.Value = parts[1]
				ins.Message = strings.Join(parts[3:], " ")
			} else {
				ins.Op, ins.Value, ins.Message = types.OpSet, parts[1], strings.Join(parts[2:], " ")
			}
		case "GET_HEADER":
			ins.Op, ins.Value, ins.Message = types.OpGetHeader, parts[1], parts[2]
		case "SET_HEADER":
			validateVar(parts[1], lineNum)
			ins.Op, ins.Value, ins.Message = types.OpSetHeader, parts[1], strings.Join(parts[2:], " ")
		case "TIME":
			ins.Op, ins.Value = types.OpTime, parts[1]
		case "INCREMENT":
			ins.Op, ins.Value = types.OpIncrement, parts[1]
		case "HTTP":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: HTTP requires method and URL", lineNum)
			}
			if strings.ToUpper(parts[1]) == "GET" {
				ins.Op, ins.Value, ins.Message = types.OpFetch, parts[2], parts[3]
			} else {
				ins.Op = types.OpPost
				ins.Message = parts[2] + " " + strings.Join(parts[3:], " ")
			}
		case "IF":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: IF missing arguments", lineNum)
			}
			currentIsIf = true

			actionIdx := -1
			for i, p := range parts {
				u := strings.ToUpper(p)
				if u == "PRINT" || u == "CALL" || u == "BLOCK" || u == "EXEC" || u == "HTTP" || u == "BREAK" || u == "INPUT" || u == "SEARCH" {
					actionIdx = i
					break
				}
			}
			if actionIdx == -1 {
				return fmt.Errorf("line %d: IF missing action", lineNum)
			}
			if strings.ToUpper(parts[actionIdx]) == "HTTP" {
				ins.Op = types.OpIfPost
				ins.Value = strings.Join(parts[1:actionIdx], " ")
				ins.Message = parts[actionIdx+2] + " " + strings.Join(parts[actionIdx+3:], " ")
			} else {
				action := strings.ToUpper(parts[actionIdx])
				switch action {
				case "PRINT":
					ins.Op = types.OpIfPrint
				case "CALL":
					ins.Op = types.OpIfCall
				case "BLOCK":
					ins.Op = types.OpIfBlock
				case "EXEC":
					ins.Op = types.OpIfExec
				case "BREAK":
					ins.Op = types.OpIfBreak
				case "INPUT":
					ins.Op = types.OpInput
				case "SEARCH":
					ins.Op = types.OpSearch
				}
				ins.Value = strings.Join(parts[1:actionIdx], " ")
				ins.Message = strings.Join(parts[actionIdx+1:], " ")
			}
		case "ELSE":
			if !lastWasIf {
				return fmt.Errorf("line %d: ELSE must follow an IF statement", lineNum)
			}
			ins.Op = types.OpElse
			action := strings.ToUpper(parts[1])
			ins.Value = "ELSE_" + action
			ins.Message = strings.Join(parts[2:], " ")
		case "PRINT":
			ins.Op, ins.Message = types.OpPrint, strings.Join(parts[1:], " ")
		case "CALL":
			ins.Op, ins.Value = types.OpCall, parts[1]
		case "SLEEP":
			ins.Op, ins.Value = types.OpSleep, parts[1]
		case "EXEC":
			ins.Op, ins.Message = types.OpExec, strings.Join(parts[1:], " ")
		case "INPUT":
			if len(parts) >= 2 {
				if err := validateVar(parts[1], lineNum); err != nil {
					return err
				}
				ins.Op = types.OpInput
				ins.Value = parts[1]
				ins.Message = strings.Join(parts[2:], " ")
			} else {
				return fmt.Errorf("line %d: INPUT requires a target variable", lineNum)
			}
		case "GET_ISP":
			ins.Op, ins.Value, ins.Message = types.OpGetISP, parts[1], parts[2]
		case "BLOCK":
			ins.Op = types.OpBlock
		case "SEARCH":
			if len(parts) < 4 {
				return fmt.Errorf("line %d: SEARCH requires path, target_var and pattern", lineNum)
			}
			ins.Op = types.OpSearch
			ins.Value = parts[2]
			ins.Message = parts[1] + "|" + strings.Join(parts[3:], " ")
		case "READ_FILE":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: READ_FILE requires path and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpReadFile, parts[1], parts[2]
		case "TOKENIZE":
			if len(parts) < 4 {
				return fmt.Errorf("line %d: TOKENIZE requires source, delimiter, and target_array", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpTokenize, parts[1], parts[2]+"|"+parts[3]
		case "ARRAY_GET":
			if len(parts) < 4 {
				return fmt.Errorf("line %d: ARRAY_GET requires array, index, and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpArrayGet, parts[1], parts[2]+"|"+parts[3]
		case "ARRAY_SET":
			if len(parts) < 4 {
				return fmt.Errorf("line %d: ARRAY_SET requires array, index, and value", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpArraySet, parts[1], parts[2]+"|"+strings.Join(parts[3:], " ")
		case "ARRAY_LEN":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: ARRAY_LEN requires array and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpArrayLen, parts[1], parts[2]
		case "INDEX_OF":
			if len(parts) < 4 {
				return fmt.Errorf("line %d: INDEX_OF requires source, search_term, and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpIndexOf, parts[1], parts[2]+"|"+parts[3]
		case "SYSTEM":
			ins.Op, ins.Message = types.OpSystem, strings.Join(parts[1:], " ")
		case "RAW":
			ins.Op, ins.Message = types.OpData, strings.Join(parts[1:], " ")
		case "REDIRECT":
			ins.Op, ins.Value = types.OpRedirect, parts[2]
		case "SPOOF":
			ins.Op, ins.Value = types.OpSpoof, parts[1]
		case "ALERT":
			ins.Op, ins.Message = types.OpAlert, strings.Join(parts[1:], " ")
		case "NUKE_CONNECTION":
			ins.Op = types.OpNuke
		case "BashKILL_PID":
			ins.Op = types.OpBashKill
		default:
			return fmt.Errorf("line %d: unknown command '%s'", lineNum, cmd)
		}

		lastWasIf = currentIsIf
		if err := prepare(&ins); err != nil {
			return fmt.Errorf("line %d: %v", lineNum, err)
		}
		stack[len(stack)-1] = append(stack[len(stack)-1], ins)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed reading source: %w", err)
	}

	fmt.Println("[Mapping Symbol Table] - SharkScript")
	time.Sleep(1000 * time.Millisecond)

	fmt.Println("[Checking for Errors] - SharkScript")
	time.Sleep(1200 * time.Millisecond)

	if len(ctrlStack) > 0 {
		last := ctrlStack[len(ctrlStack)-1]
		return fmt.Errorf("syntax error: unclosed block type '%s' (name: %s, val: %s)", last.op, last.name, last.val)
	}

	fmt.Println("[Optimizing Bytecode] - SHARK01")
	time.Sleep(1000 * time.Millisecond)

	destPath := strings.TrimSuffix(srcPath, ".shark") + ".shx"
	dest, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer dest.Close()

	dest.Write([]byte("SHARK01"))

	script := types.CompiledScript{
		Main:      stack[0],
		Functions: functions,
		Imports:   imports,
	}

	encoder := gob.NewEncoder(dest)
	if err := encoder.Encode(script); err != nil {
		return fmt.Errorf("failed to encode bytecode: %w", err)
	}

	totalInstructions := len(stack[0])
	for _, fn := range functions {
		totalInstructions += len(fn)
	}

	fmt.Printf("\n--- Compilation Successful ---\n")
	fmt.Printf("Source:       %s\n", srcPath)
	fmt.Printf("Lines:        %d\n", lineNum)
	fmt.Printf("Instructions: %d\n", totalInstructions)
	fmt.Printf("Functions:    %d\n", len(functions))
	fmt.Printf("Binary Size:  %s\n\n", destPath)

	return nil
}
