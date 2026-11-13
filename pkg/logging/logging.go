// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package logging builds the logger shared by every auth-operator binary from
// --log-format, --log-level and --verbosity (or LOG_FORMAT, LOG_LEVEL and
// LOG_VERBOSITY).
package logging

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/go-logr/logr"
	uberzap "go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// Environment variables used when the matching flag is not given.
const (
	EnvFormat    = "LOG_FORMAT"
	EnvLevel     = "LOG_LEVEL"
	EnvVerbosity = "LOG_VERBOSITY"
)

// ErrorsOnly is the verbosity of --log-level=error: only Error lines are written.
const ErrorsOnly = -1

// Levels maps --log-level names to verbosities. logr has no warning level;
// warnings are V(0) lines, so warn and info are the same.
var Levels = map[string]int{"error": ErrorsOnly, "warn": 0, "info": 0, "debug": 4}

// Options are the logging settings of a binary.
type Options struct {
	Format    string
	Level     string
	Verbosity int
}

// BindFlags registers --log-format, --log-level, --verbosity and -v on fs.
func (o *Options) BindFlags(fs *flag.FlagSet, defaultVerbosity int) {
	fs.StringVar(&o.Format, "log-format", "text",
		"Log output format: text (klog) or json (one JSON object per line). Env: "+EnvFormat+".")
	fs.StringVar(&o.Level, "log-level", "",
		"Named log level: error (errors only), warn or info (V(0)), debug (V(4)). "+
			"Fails if --verbosity is also set to a different level. Env: "+EnvLevel+".")
	fs.IntVar(&o.Verbosity, "verbosity", defaultVerbosity, "Log verbosity (0-9, higher is more verbose). Env: "+EnvVerbosity+".")
	fs.IntVar(&o.Verbosity, "v", defaultVerbosity, "Shorthand for --verbosity.")
}

// Visited reports the flags set on the command line of a parsed fs.
func Visited(fs *flag.FlagSet) func(name string) bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return func(name string) bool { return set[name] }
}

// Resolve applies the LOG_* environment variables to the options whose flag
// was not set, then --log-level. It fails on unknown values and when a named
// level and an explicit verbosity disagree.
func (o *Options) Resolve(set func(name string) bool) error {
	if v := os.Getenv(EnvFormat); v != "" && !set("log-format") {
		o.Format = v
	}
	if v := os.Getenv(EnvLevel); v != "" && !set("log-level") {
		o.Level = v
	}
	verbositySet := set("verbosity") || set("v")
	if v := os.Getenv(EnvVerbosity); v != "" && !verbositySet {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid %s %q: %w", EnvVerbosity, v, err)
		}
		o.Verbosity, verbositySet = n, true
	}
	if o.Format != "text" && o.Format != "json" {
		return fmt.Errorf("invalid log format %q: must be text or json", o.Format)
	}
	if o.Verbosity < 0 {
		return fmt.Errorf("invalid verbosity %d: must not be negative", o.Verbosity)
	}
	if o.Level == "" {
		return nil
	}
	level, ok := Levels[o.Level]
	if !ok {
		return fmt.Errorf("invalid log level %q: must be error, warn, info or debug", o.Level)
	}
	if verbositySet && o.Verbosity != level {
		return fmt.Errorf("log level %q (verbosity %d) conflicts with verbosity %d", o.Level, level, o.Verbosity)
	}
	o.Verbosity = level
	return nil
}

// Logger returns the logger for resolved options. json writes to w; text is
// klog's own output on stderr. It also sets klog's verbosity and, for json,
// routes klog (client-go) through the logger.
func (o Options) Logger(w io.Writer) (logr.Logger, error) {
	klogFlags := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlags)
	if err := klogFlags.Set("v", strconv.Itoa(max(o.Verbosity, 0))); err != nil {
		return logr.Logger{}, fmt.Errorf("set klog verbosity: %w", err)
	}
	if o.Format == "json" {
		v := o.Verbosity
		log := zap.New(
			zap.WriteTo(w),
			// logr V(n) is zap level -n; ErrorsOnly leaves warn and error.
			zap.Level(uberzap.LevelEnablerFunc(func(l zapcore.Level) bool { return int(l) >= -v })),
			func(o *zap.Options) { o.TimeEncoder = zapcore.RFC3339NanoTimeEncoder },
		)
		klog.SetLogger(log)
		return log, nil
	}
	log := klog.NewKlogr()
	if o.Verbosity == ErrorsOnly {
		log = logr.New(errorsOnly{log.GetSink()})
	}
	return log, nil
}

// errorsOnly drops Info lines at every level and keeps Error lines.
type errorsOnly struct{ logr.LogSink }

// Enabled reports false so that no Info line is written.
func (errorsOnly) Enabled(int) bool { return false }

// WithValues keeps the wrapper on the derived sink.
func (s errorsOnly) WithValues(kv ...any) logr.LogSink {
	return errorsOnly{s.LogSink.WithValues(kv...)}
}

// WithName keeps the wrapper on the derived sink.
func (s errorsOnly) WithName(name string) logr.LogSink { return errorsOnly{s.LogSink.WithName(name)} }

// WithCallDepth forwards call depth so klog reports the caller's file and line.
func (s errorsOnly) WithCallDepth(depth int) logr.LogSink {
	if c, ok := s.LogSink.(logr.CallDepthLogSink); ok {
		return errorsOnly{c.WithCallDepth(depth)}
	}
	return s
}
