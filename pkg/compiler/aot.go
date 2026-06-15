package compiler

import (
	"fmt"
	"strconv"
	"strings"

	"sharkscript/pkg/types"
)

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
