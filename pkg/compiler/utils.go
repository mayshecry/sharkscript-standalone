package compiler

import (
	"strconv"
	"strings"
)

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
