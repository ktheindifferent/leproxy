package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var levelStrings = map[Level]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelWarn:  "WARN",
	LevelError: "ERROR",
	LevelFatal: "FATAL",
}

type Logger struct {
	mu       sync.RWMutex
	level    Level
	output   io.Writer
	jsonMode bool
	prefix   string
	fields   map[string]interface{}
}

var defaultLogger = &Logger{
	level:    LevelInfo,
	output:   os.Stdout,
	jsonMode: false,
	fields:   make(map[string]interface{}),
}

func SetLevel(level Level) {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	defaultLogger.level = level
}

func SetJSONMode(enabled bool) {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	defaultLogger.jsonMode = enabled
}

func SetOutput(w io.Writer) {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	defaultLogger.output = w
}

func SetPrefix(prefix string) {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	defaultLogger.prefix = prefix
}

func ParseLevel(s string) (Level, error) {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return LevelDebug, nil
	case "INFO":
		return LevelInfo, nil
	case "WARN", "WARNING":
		return LevelWarn, nil
	case "ERROR":
		return LevelError, nil
	case "FATAL":
		return LevelFatal, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level: %s", s)
	}
}

type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
}

func (l *Logger) log(level Level, msg string, fields map[string]interface{}) {
	l.mu.RLock()
	if level < l.level {
		l.mu.RUnlock()
		return
	}
	output := l.output
	jsonMode := l.jsonMode
	prefix := l.prefix
	globalFields := make(map[string]interface{})
	for k, v := range l.fields {
		globalFields[k] = v
	}
	l.mu.RUnlock()

	for k, v := range fields {
		globalFields[k] = v
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     levelStrings[level],
		Message:   msg,
		Fields:    globalFields,
	}

	if level >= LevelError {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			parts := strings.Split(file, "/")
			if len(parts) > 2 {
				file = strings.Join(parts[len(parts)-2:], "/")
			}
			entry.Caller = fmt.Sprintf("%s:%d", file, line)
		}
	}

	var out string
	if jsonMode {
		b, _ := json.Marshal(entry)
		out = string(b) + "\n"
	} else {
		out = fmt.Sprintf("%s [%s] ", entry.Timestamp, entry.Level)
		if prefix != "" {
			out += prefix + " "
		}
		out += entry.Message
		if len(entry.Fields) > 0 {
			out += " "
			for k, v := range entry.Fields {
				out += fmt.Sprintf("%s=%v ", k, v)
			}
		}
		if entry.Caller != "" {
			out += fmt.Sprintf(" (%s)", entry.Caller)
		}
		out += "\n"
	}

	fmt.Fprint(output, out)

	if level == LevelFatal {
		os.Exit(1)
	}
}

func Debug(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	defaultLogger.log(LevelDebug, msg, f)
}

func Info(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	defaultLogger.log(LevelInfo, msg, f)
}

func Warn(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	defaultLogger.log(LevelWarn, msg, f)
}

func Error(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	defaultLogger.log(LevelError, msg, f)
}

func Fatal(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	defaultLogger.log(LevelFatal, msg, f)
}

func WithFields(fields map[string]interface{}) *Logger {
	newLogger := &Logger{
		level:    defaultLogger.level,
		output:   defaultLogger.output,
		jsonMode: defaultLogger.jsonMode,
		prefix:   defaultLogger.prefix,
		fields:   make(map[string]interface{}),
	}
	
	defaultLogger.mu.RLock()
	for k, v := range defaultLogger.fields {
		newLogger.fields[k] = v
	}
	defaultLogger.mu.RUnlock()
	
	for k, v := range fields {
		newLogger.fields[k] = v
	}
	
	return newLogger
}

func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(LevelDebug, msg, f)
}

func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(LevelInfo, msg, f)
}

func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(LevelWarn, msg, f)
}

func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(LevelError, msg, f)
}

func (l *Logger) Fatal(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(LevelFatal, msg, f)
}

func mergeFields(fields ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, f := range fields {
		for k, v := range f {
			result[k] = v
		}
	}
	return result
}