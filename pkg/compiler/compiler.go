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
	"time"

	"sharkscript/pkg/types"
)

func Compile(srcPath string) error {
	fmt.Printf(" Initializing Build: %s\n", srcPath)

	script, lineNum, err := Parse(srcPath)
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

	fmt.Printf("✔ Bytecode Exported: %s\n", destPath)
	printSuccess(srcPath, destPath, lineNum, script)
	return nil
}

func Parse(srcPath string) (types.CompiledScript, int, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return types.CompiledScript{}, 0, fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	fmt.Printf("[Parsing Source] - %s\n", srcPath)
	scanner := bufio.NewScanner(src)
	lineNum := 0

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
		upperExpr := strings.ToUpper(expr)
		operators := []struct {
			token string
			op    types.LogicOp
		}{
			{" < ", types.LogLt}, {" > ", types.LogGt}, {" == ", types.LogEq},
			{"PROTO ", types.LogProto}, {"CONTAINS ", types.LogContains},
		}
		for _, o := range operators {
			if idx := strings.Index(upperExpr, o.token); idx != -1 {
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

		if strings.Contains(ins.Message, "%") {
			ins.Message = strings.ReplaceAll(ins.Message, "\\033", "\x1b")
			ins.TemplateParts = parseTemplate(ins.Message)
		}

		if ins.Op == types.OpWhile || (ins.Op >= types.OpIfPrint && ins.Op <= types.OpIfBreak) {
			ins.Condition = compileLogic(ins.Value)
			if ins.Condition == nil {
				return fmt.Errorf("invalid condition expression: '%s'", ins.Value)
			}
		}

		if ins.Op == types.OpSetExpr && ins.IsStatic {
			ins.Message = evalMath(ins.Message)
			ins.Op = types.OpSet
		}

		return nil
	}

	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		if !usesBypass && strings.Contains(line, "%BYPASS_TIME%") {
			usesBypass = true
		}
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
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: LOOP requires a count", lineNum)
			}
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "LOOP", val: parts[1]})
			continue
		}

		if cmd == "PARALLEL" && len(parts) > 1 && strings.ToUpper(parts[1]) == "LOOP" {
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: PARALLEL LOOP requires a count", lineNum)
			}
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "PARALLEL_LOOP", val: parts[2]})
			continue
		}

		if cmd == "ENDLOOP" {
			if len(ctrlStack) == 0 || (ctrlStack[len(ctrlStack)-1].op != "LOOP" && ctrlStack[len(ctrlStack)-1].op != "PARALLEL_LOOP") {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: ENDLOOP without LOOP", lineNum)
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

			if op == types.OpParallelLoop && ctrl.val != "" {
				if count, err := strconv.Atoi(ctrl.val); err == nil && count > 0 && count < 128 {
					op = types.OpLoop
				}
			}

			ins := types.Instruction{Op: op, Value: ctrl.val, Body: body, NeedsIteration: containsIter(body)}
			if len(body) == 1 && body[0].Op == types.OpPrint {
				ins.IsSinglePrintLoop = true
			}
			if err := prepare(&ins); err != nil {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: %v", lineNum, err)
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
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: ENDWHILE without WHILE", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			ins := types.Instruction{Op: types.OpWhile, Value: ctrl.val, Body: body}
			if err := prepare(&ins); err != nil {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: %v", lineNum, err)
			}
			stack[len(stack)-1] = append(stack[len(stack)-1], ins)
			continue
		}

		if cmd == "FUNCTION" {
			if len(parts) < 2 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: FUNCTION requires a name", lineNum)
			}
			if _, exists := functions[parts[1]]; exists {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: redeclaration of function '%s'", lineNum, parts[1])
			}
			stack = append(stack, []types.Instruction{})
			ctrlStack = append(ctrlStack, control{op: "FUNCTION", name: parts[1]})
			continue
		}

		if cmd == "ENDFUNCTION" {
			if len(ctrlStack) == 0 || ctrlStack[len(ctrlStack)-1].op != "FUNCTION" {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: ENDFUNCTION without FUNCTION", lineNum)
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
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: SET requires var and val", lineNum)
			}
			if err := validateVar(parts[1], lineNum); err != nil {
				return types.CompiledScript{}, lineNum, err
			}
			if len(parts) > 2 && parts[2] == "=" {
				ins.Op = types.OpSetExpr
				ins.Value = parts[1]
				ins.Message = strings.Join(parts[3:], " ")
			} else {
				ins.Op, ins.Value, ins.Message = types.OpSet, parts[1], strings.Join(parts[2:], " ")
			}
		case "GET_HEADER":
			ins.Op, ins.Value, ins.Message = types.OpGetHeader, parts[1], parts[2]
		case "SET_HEADER":
			if err := validateVar(parts[1], lineNum); err != nil {
				return types.CompiledScript{}, lineNum, err
			}
			ins.Op, ins.Value, ins.Message = types.OpSetHeader, parts[1], strings.Join(parts[2:], " ")
		case "TIME":
			ins.Op, ins.Value = types.OpTime, parts[1]
		case "INCREMENT":
			ins.Op, ins.Value = types.OpIncrement, parts[1]
		case "HTTP":
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: HTTP requires method and URL", lineNum)
			}
			if strings.ToUpper(parts[1]) == "GET" {
				ins.Op, ins.Value, ins.Message = types.OpFetch, parts[2], parts[3]
			} else {
				ins.Op = types.OpPost
				ins.Message = parts[2] + " " + strings.Join(parts[3:], " ")
			}
		case "IF":
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: IF missing arguments", lineNum)
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
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: IF missing action", lineNum)
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
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: ELSE must follow an IF statement", lineNum)
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
			ins.Op, ins.Message = types.OpExec, strings.Join(parts[1:], " ")
		case "INPUT":
			if len(parts) >= 2 {
				if err := validateVar(parts[1], lineNum); err != nil {
					return types.CompiledScript{}, lineNum, err
				}
				ins.Op = types.OpInput
				ins.Value = parts[1]
				ins.Message = strings.Join(parts[2:], " ")
			} else {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: INPUT requires a target variable", lineNum)
			}
		case "GET_ISP":
			ins.Op, ins.Value, ins.Message = types.OpGetISP, parts[1], parts[2]
		case "BLOCK":
			ins.Op = types.OpBlock
		case "SEARCH":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: SEARCH requires path, target_var and pattern", lineNum)
			}
			ins.Op = types.OpSearch
			ins.Value = parts[2]
			ins.Message = parts[1] + "|" + strings.Join(parts[3:], " ")
		case "READ_FILE":
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: READ_FILE requires path and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpReadFile, parts[1], parts[2]
		case "TOKENIZE":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: TOKENIZE requires source, delimiter, and target_array", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpTokenize, parts[1], parts[2]+"|"+parts[3]
		case "ARRAY_GET":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: ARRAY_GET requires array, index, and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpArrayGet, parts[1], parts[2]+"|"+parts[3]
		case "ARRAY_SET":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: ARRAY_SET requires array, index, and value", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpArraySet, parts[1], parts[2]+"|"+strings.Join(parts[3:], " ")
		case "ARRAY_LEN":
			if len(parts) < 3 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: ARRAY_LEN requires array and target_var", lineNum)
			}
			ins.Op, ins.Value, ins.Message = types.OpArrayLen, parts[1], parts[2]
		case "INDEX_OF":
			if len(parts) < 4 {
				return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: INDEX_OF requires source, search_term, and target_var", lineNum)
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
			return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: unknown command '%s'", lineNum, cmd)
		}

		lastWasIf = currentIsIf
		if err := prepare(&ins); err != nil {
			return types.CompiledScript{}, lineNum, fmt.Errorf("line %d: %v", lineNum, err)
		}
		stack[len(stack)-1] = append(stack[len(stack)-1], ins)
	}

	if err := scanner.Err(); err != nil {
		return types.CompiledScript{}, lineNum, fmt.Errorf("failed reading source: %w", err)
	}

	if len(ctrlStack) > 0 {
		last := ctrlStack[len(ctrlStack)-1]
		return types.CompiledScript{}, lineNum, fmt.Errorf("syntax error: unclosed block type '%s' (name: %s, val: %s)", last.op, last.name, last.val)
	}

	return types.CompiledScript{
		Main:           stack[0],
		Functions:      functions,
		Imports:        imports,
		UsesBypassTime: usesBypass,
	}, lineNum, nil
}

func printSuccess(_, destPath string, lineNum int, script types.CompiledScript) {
	totalInstructions := len(script.Main)
	for _, fn := range script.Functions {
		totalInstructions += len(fn)
	}
	fmt.Printf("\n--- SharkScript Build Successful --- \n")
	fmt.Printf("Target:       %s\n", destPath)
	fmt.Printf("Size:         %d lines -> %d opcodes\n", lineNum, totalInstructions)
	fmt.Printf("Functions:    %d defined\n", len(script.Functions))
	fmt.Printf("Optimizations: Constant Folding, Loop-Unrolling, Parallel-Downgrade, Empty-Loop-Bypass\n")
	fmt.Printf("Build Mode:   [OPTIMIZED MAX PERFORMANCE]\n")
	fmt.Printf("-----------------------------------------\n\n")
}

func CompileAOT(srcPath string, targetOS string) error {
	script, lineNum, err := Parse(srcPath)
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

	fmt.Println("[Invoking Native Toolchain] - Go 1.21+ Backend")
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outputBin, tmpFile)
	cmd.Env = append(os.Environ(), "GOOS="+targetOS)

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("AOT Build Failed: %s\n%s", err, string(out))
	}

	printSuccess(srcPath, outputBin+" (NATIVE)", lineNum, script)
	return nil
}
func GenerateGo(script types.CompiledScript) string {
	required := map[string]bool{
		"sharkscript/pkg/types": true,
		"bufio":                 true,
		"os":                    true,
		"strings":               false,
		"strconv":               false,
		"fmt":                   false,
	}

	needsEvalMath := false
	needsExpandVars := false

	var analyze func([]types.Instruction)
	analyze = func(insts []types.Instruction) {
		for _, ins := range insts {
			if strings.Contains(ins.Message, "%") || strings.Contains(ins.Value, "%") {
				needsExpandVars = true
			}
			switch ins.Op {
			case types.OpPrint:
				required["strings"] = true
			case types.OpInput:
				required["fmt"] = true
				required["bufio"] = true
				required["strings"] = true
			case types.OpWhile, types.OpIfCall, types.OpIfBreak, types.OpIfPrint:
				required["strings"] = true
			case types.OpSet, types.OpSetExpr:
				if ins.Op == types.OpSetExpr {
					required["strconv"] = true
					needsEvalMath = true
				}
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
				required["bufio"] = true
				required["strconv"] = true
			case types.OpTime, types.OpTimerStart, types.OpTimerEnd:
				required["time"] = true
				required["strconv"] = true
			case types.OpReadFile:
				required["os"] = true
			}
			if len(ins.Body) > 0 {
				analyze(ins.Body)
			}
		}
	}

	analyze(script.Main)
	for _, fn := range script.Functions {
		analyze(fn)
	}

	var sb strings.Builder
	sb.WriteString("package main\n\nimport (\n")
	for pkg, req := range required {
		if req {
			fmt.Fprintf(&sb, "\t\"%s\"\n", pkg)
		}
	}
	sb.WriteString(")\n\n")

	sb.WriteString("func main() {\n")
	sb.WriteString("\tout := bufio.NewWriter(os.Stdout)\n")
	sb.WriteString("\tExecute(&types.PacketData{}, make(map[string]string), make(map[string][]string), out)\n")
	sb.WriteString("\tout.Flush()\n")
	sb.WriteString("}\n\n")

	for name, body := range script.Functions {
		fmt.Fprintf(&sb, "func %s(pkt *types.PacketData, vars map[string]string, arrays map[string][]string, out *bufio.Writer) bool {\n", name)
		for _, ins := range body {
			sb.WriteString(translateToGo(ins, 1))
		}
		sb.WriteString("\treturn false\n}\n\n")
	}

	sb.WriteString("func Execute(pkt *types.PacketData, vars map[string]string, arrays map[string][]string, out *bufio.Writer) bool {\n")
	sb.WriteString("\t_ = pkt\n")
	sb.WriteString("\t_ = vars\n")
	sb.WriteString("\t_ = arrays\n")
	for _, ins := range script.Main {
		sb.WriteString(translateToGo(ins, 1))
	}
	sb.WriteString("\treturn false\n}\n")

	if needsExpandVars {
		sb.WriteString(`
func expandVars(input string, vars map[string]string) string {
	if !strings.Contains(input, "%") { return input }
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
		val, ok := vars[key]
		if !ok {
			sb.WriteByte('%'); sb.WriteString(key); sb.WriteByte('%')
		} else {
			f, err := strconv.ParseFloat(val, 64)
			if err == nil && f > 0 && f < 1 {
				if strings.HasPrefix(curr[end+1:], "ms") {
					if f < 0.001 {
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
						if f < 0.000001 {
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
		curr = curr[end+1:]
	}
	return sb.String()
}
`)
	}

	if needsEvalMath {
		sb.WriteString(`
func evalMath(expr string) string {
	tokens := strings.Fields(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(expr, "+", " + "), "-", " - "), "*", " * "), "/", " / "))
	if len(tokens) < 3 { return expr }
	var highPrec []string
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if (t == "*" || t == "/") && len(highPrec) > 0 {
			left, _ := strconv.ParseFloat(highPrec[len(highPrec)-1], 64)
			i++; if i >= len(tokens) { break }
			right, _ := strconv.ParseFloat(tokens[i], 64)
			var res float64
			if t == "*" { res = left * right } else if right != 0 { res = left / right }
			highPrec[len(highPrec)-1] = strconv.FormatFloat(res, 'f', 9, 64)
		} else { highPrec = append(highPrec, t) }
	}
	if len(highPrec) == 0 { return "0" }
	total, _ := strconv.ParseFloat(highPrec[0], 64)
	for i := 1; i < len(highPrec); i += 2 {
		if i+1 >= len(highPrec) { break }
		op := highPrec[i]
		val, _ := strconv.ParseFloat(highPrec[i+1], 64)
		switch op {
		case "+": total += val
		case "-": total -= val
		}
	}
	return strconv.FormatFloat(total, 'f', 9, 64)
}
`)
	}

	return sb.String()
}

func generateGoLogic(expr *types.LogicExpr) string {
	if expr == nil {
		return "false"
	}
	switch expr.Op {
	case types.LogOr:
		return "(" + generateGoLogic(expr.Left) + " || " + generateGoLogic(expr.Right) + ")"
	case types.LogAnd:
		return "(" + generateGoLogic(expr.Left) + " && " + generateGoLogic(expr.Right) + ")"
	case types.LogEq:
		return fmt.Sprintf("(%s == %s)", generateGoLogic(expr.Left), generateGoLogic(expr.Right))
	case types.LogGt:
		return fmt.Sprintf("(%s > %s)", generateGoLogic(expr.Left), generateGoLogic(expr.Right))
	case types.LogLt:
		return fmt.Sprintf("(%s < %s)", generateGoLogic(expr.Left), generateGoLogic(expr.Right))
	case types.LogVar:
		return fmt.Sprintf("vars[%q]", expr.Value)
	case types.LogConst:
		return fmt.Sprintf("%q", expr.Value)
	default:
		return "false"
	}
}

func translateToGo(ins types.Instruction, depth int) string {
	indent := strings.Repeat("\t", depth)

	generateInlinedExpand := func(input string, targetWriter string) string {
		var expansion strings.Builder
		parts := parseTemplate(input)
		for i, p := range parts {
			if i%2 == 0 {
				if p != "" {
					fmt.Fprintf(&expansion, "%s%s.WriteString(%q)\n", indent, targetWriter, p)
				}
			} else {
				switch p {
				case "ITER":
					fmt.Fprintf(&expansion, "%s%s.Write(strconv.AppendInt(nil, int64(pkt.Iteration), 10))\n", indent, targetWriter)
				case "CORE":
					fmt.Fprintf(&expansion, "%s%s.Write(strconv.AppendInt(nil, int64(pkt.Core), 10))\n", indent, targetWriter)
				default:
					fmt.Fprintf(&expansion, "%sif v, ok := vars[%q]; ok { %s.WriteString(v) } else { %s.WriteString(\"%%%s%%\") }\n",
						indent, p, targetWriter, targetWriter, p)
				} // How sinister
			}
		}
		return expansion.String()
	}
	// Lowkey, i be losing my sanity but anyways:
	// Yo Gurt
	// Gurt: Yo!
	switch ins.Op {
	case types.OpLoop:
		res := fmt.Sprintf("%s{\n", indent)
		if ins.IsStatic {
			res += fmt.Sprintf("%s\tfor i := 0; i < %d; i++ {\n", indent, ins.IntValue)
		} else {
			res += fmt.Sprintf("%s\tcount, _ := strconv.Atoi(vars[\"%s\"])\n", indent, ins.Value)
			res += fmt.Sprintf("%s\tfor i := 0; i < count; i++ {\n", indent)
		}

		res += fmt.Sprintf("%s\t\tpkt.Iteration = i\n", indent)
		if ins.IsSinglePrintLoop {
			res += generateInlinedExpand(ins.Body[0].Message, "out")
			res += fmt.Sprintf("%s\t\tout.WriteByte('\\n')\n", indent)
		} else {
			for _, bIns := range ins.Body {
				res += translateToGo(bIns, depth+2)
			}
		}
		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res

	case types.OpWhile:
		res := fmt.Sprintf("%sfor %s {\n", indent, generateGoLogic(ins.Condition))
		for _, bIns := range ins.Body {
			res += translateToGo(bIns, depth+1)
		}
		res += fmt.Sprintf("%s}\n", indent)
		return res

	case types.OpInput:
		res := fmt.Sprintf("%sout.Flush()\n", indent)
		res += fmt.Sprintf("%sfmt.Print(expandVars(%q, vars))\n", indent, ins.Message)
		res += fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\treader := bufio.NewReader(os.Stdin)\n", indent)
		res += fmt.Sprintf("%s\ttext, _ := reader.ReadString('\\n')\n", indent)
		res += fmt.Sprintf("%s\tvars[%q] = strings.TrimSpace(text)\n", indent, ins.Value)
		res += fmt.Sprintf("%s}\n", indent)
		return res

	case types.OpTimerStart:
		return fmt.Sprintf("%spkt.Timestamp = time.Now()\n", indent)
	case types.OpTimerEnd:
		return fmt.Sprintf("%svars[\"%s\"] = strconv.FormatFloat(time.Since(pkt.Timestamp).Seconds(), 'f', 9, 64)\n", indent, ins.Value)
	case types.OpTime:
		return fmt.Sprintf("%svars[\"%s\"] = strconv.FormatFloat(float64(time.Now().UnixNano())/1e6, 'f', 9, 64)\n", indent, ins.Value)
	case types.OpSet:
		if !strings.Contains(ins.Message, "%") {
			return fmt.Sprintf("%svars[%q] = %q\n", indent, ins.Value, ins.Message)
		}
		return fmt.Sprintf("%svars[\"%s\"] = expandVars(%q, vars)\n", indent, ins.Value, ins.Message)
	case types.OpSetExpr:
		return fmt.Sprintf("%svars[\"%s\"] = evalMath(expandVars(%q, vars))\n", indent, ins.Value, ins.Message)
	case types.OpIncrement:
		return fmt.Sprintf("%s{\n%s\tv, _ := strconv.Atoi(vars[\"%s\"])\n%s\tvars[\"%s\"] = strconv.Itoa(v + 1)\n%s}\n", indent, indent, ins.Value, indent, ins.Value, indent)
	case types.OpIfCall:
		return fmt.Sprintf("%sif %s { if %s(pkt, vars, arrays, out) { return true } }\n", indent, generateGoLogic(ins.Condition), ins.Message)
	case types.OpIfBreak:
		return fmt.Sprintf("%sif %s { break }\n", indent, generateGoLogic(ins.Condition))
	case types.OpCall:
		return fmt.Sprintf("%sif %s(pkt, vars, arrays, out) { return true }\n", indent, ins.Value)
	case types.OpReadFile:
		return fmt.Sprintf("%s{ data, _ := os.ReadFile(expandVars(%q, vars)); vars[%q] = string(data) }\n", indent, ins.Value, ins.Message)
	case types.OpTokenize:
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tsrc := expandVars(%q, vars)\n", indent, ins.Value)
		res += fmt.Sprintf("%s\tmParts := strings.SplitN(%q, \"|\", 2)\n", indent, ins.Message)
		res += fmt.Sprintf("%s\tvar tokens []string\n", indent)
		res += fmt.Sprintf("%s\tswitch expandVars(mParts[0], vars) { case \"SPACE\": tokens = strings.Fields(src); case \"NEWLINE\": tokens = strings.Split(src, \"\\n\"); default: tokens = strings.Split(src, expandVars(mParts[0], vars)) }\n", indent)
		res += fmt.Sprintf("%s\tarrays[mParts[1]] = tokens\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpArrayGet:
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tmParts := strings.SplitN(%q, \"|\", 2)\n", indent, ins.Message)
		res += fmt.Sprintf("%s\tidx, _ := strconv.Atoi(expandVars(mParts[0], vars))\n", indent)
		res += fmt.Sprintf("%s\tif arr, ok := arrays[%q]; ok && idx >= 0 && idx < len(arr) { vars[mParts[1]] = arr[idx] }\n", indent, ins.Value)
		res += fmt.Sprintf("%s}\n", indent)
		return res
	case types.OpParallelLoop, types.OpEmptyParallelLoop:
		if ins.Op == types.OpEmptyParallelLoop {
			res := fmt.Sprintf("%s{\n", indent)
			res += fmt.Sprintf("%s\tstart := time.Now()\n", indent)
			if ins.Duration > 0 {
				res += fmt.Sprintf("%s\ttime.Sleep(time.Duration(%d))\n", indent, int64(ins.Duration))
			}
			res += fmt.Sprintf("%s\tvars[\"BYPASS_TIME\"] = strconv.FormatFloat(float64(time.Since(start).Nanoseconds())/1e6, 'f', 9, 64)\n", indent)
			res += fmt.Sprintf("%s}\n", indent)
			return res
		}
		res := fmt.Sprintf("%s{\n", indent)
		res += fmt.Sprintf("%s\tsnapshot := make(map[string]string, len(vars))\n", indent)
		res += fmt.Sprintf("%s\tfor k, v := range vars { snapshot[k] = v }\n", indent)
		res += fmt.Sprintf("%s\tnumWorkers := runtime.GOMAXPROCS(0)\n", indent)
		if ins.IsStatic {
			res += fmt.Sprintf("%s\tcount := %d\n", indent, ins.IntValue)
		} else {
			res += fmt.Sprintf("%s\tcount, _ := strconv.Atoi(vars[\"%s\"])\n", indent, ins.Value)
		}

		res += fmt.Sprintf("%s\tvar wg sync.WaitGroup\n", indent)
		res += fmt.Sprintf("%s\tbuffers := make([]*bytes.Buffer, numWorkers)\n", indent)
		res += fmt.Sprintf("%s\twg.Add(numWorkers)\n", indent)
		res += fmt.Sprintf("%s\tfor w := 0; w < numWorkers; w++ {\n", indent)
		res += fmt.Sprintf("%s\t\tbuffers[w] = bytes.NewBuffer(nil)\n", indent)

		if ins.IsSinglePrintLoop {
			res += fmt.Sprintf("%s\t\tgo func(id int, lb *bytes.Buffer) {\n", indent)
			res += fmt.Sprintf("%s\t\t\tdefer wg.Done()\n", indent)
			res += fmt.Sprintf("%s\t\t\tlp := *pkt; lp.Core = id + 1\n", indent)
			res += fmt.Sprintf("%s\t\t\tfor i := (count * id) / numWorkers; i < (count * (id + 1)) / numWorkers; i++ {\n", indent)
			res += fmt.Sprintf("%s\t\t\t\tlp.Iteration = i\n", indent)
			res += strings.ReplaceAll(generateInlinedExpand(ins.Body[0].Message, "lb"), "vars", "snapshot")
			res += fmt.Sprintf("%s\t\t\t\tlb.WriteByte('\\n')\n", indent)
			res += fmt.Sprintf("%s\t\t\t}\n", indent)
			res += fmt.Sprintf("%s\t\t}(w, buffers[w])\n", indent)
		} else {
			res += fmt.Sprintf("%s\t\tgo func(workerID int, localBuf *bytes.Buffer) {\n", indent)
			res += fmt.Sprintf("%s\t\t\tdefer wg.Done()\n", indent)
			res += fmt.Sprintf("%s\t\t\tlp := *pkt; lp.Core = workerID + 1\n", indent)
			res += fmt.Sprintf("%s\t\t\tlocalOut := bufio.NewWriter(localBuf)\n", indent)
			res += fmt.Sprintf("%s\t\t\tvars := snapshot\n", indent)
			res += fmt.Sprintf("%s\t\t\t_ = vars\n", indent)
			res += fmt.Sprintf("%s\t\t\tfor i := (count * workerID) / numWorkers; i < (count * (workerID + 1)) / numWorkers; i++ {\n", indent)
			res += fmt.Sprintf("%s\t\t\t\tlp.Iteration = i\n", indent)
			for _, bIns := range ins.Body {
				res += strings.ReplaceAll(translateToGo(bIns, depth+4), "out.", "localOut.")
			}
			res += fmt.Sprintf("%s\t\t\t}\n", indent)
			res += fmt.Sprintf("%s\t\t\tlocalOut.Flush()\n", indent)
			res += fmt.Sprintf("%s\t\t}(w, buffers[w])\n", indent)
		}

		res += fmt.Sprintf("%s\t}\n", indent)
		res += fmt.Sprintf("%s\twg.Wait()\n", indent)
		res += fmt.Sprintf("%s\tfor _, b := range buffers { out.Write(b.Bytes()) }\n", indent)
		res += fmt.Sprintf("%s}\n", indent)
		return res

	case types.OpPrint:
		return generateInlinedExpand(ins.Message, "out") + fmt.Sprintf("%sout.WriteByte('\\n')\n", indent)
	default:
		return fmt.Sprintf("%s// Unsupported Op: %d\n", indent, ins.Op)
	}
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

func evalMath(expr string) string {
	tokens := make([]string, 0, 8)
	start := -1
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			if start != -1 {
				tokens = append(tokens, expr[start:i])
				start = -1
			}
			continue
		}
		if c == '+' || c == '-' || c == '*' || c == '/' {
			if start != -1 {
				tokens = append(tokens, expr[start:i])
			}
			tokens = append(tokens, string(c))
			start = -1
		} else if start == -1 {
			start = i
		}
	}
	if start != -1 {
		tokens = append(tokens, expr[start:])
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
		switch op {
		case "+":
			total += val
		case "-":
			total -= val
		}
	}

	return strconv.FormatFloat(total, 'f', 9, 64)
}
