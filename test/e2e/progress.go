package e2e

import (
	"fmt"
	"time"

	"github.com/onsi/ginkgo/v2"
)

// TestProgress tracks test execution progress with step-by-step details
type TestProgress struct {
	SuiteName      string
	TotalSteps     int
	CompletedSteps int
	StartTime      time.Time
	StepStartTime  time.Time
	StepTimes      []time.Duration
}

// NewTestProgress creates a new progress tracker
// Usage: progress := NewTestProgress("Helm Installation", 7)
func NewTestProgress(suiteName string, totalSteps int) *TestProgress {
	return &TestProgress{
		SuiteName:  suiteName,
		TotalSteps: totalSteps,
		StartTime:  time.Now(),
		StepTimes:  make([]time.Duration, 0, totalSteps),
	}
}

// Step marks the beginning of a test step and prints progress
// Usage: done := progress.Step("Building operator image"); buildImage(); done()
func (tp *TestProgress) Step(name string) func() {
	w := ginkgo.GinkgoWriter
	stepStart := time.Now()
	tp.StepStartTime = stepStart
	tp.CompletedSteps++

	percentage := float64(tp.CompletedSteps) / float64(tp.TotalSteps) * 100
	elapsed := time.Since(tp.StartTime)

	// Estimate remaining time based on average step duration
	var estimatedRemaining time.Duration
	if tp.CompletedSteps > 1 {
		avgStepTime := elapsed / time.Duration(tp.CompletedSteps)
		remainingSteps := tp.TotalSteps - tp.CompletedSteps
		estimatedRemaining = avgStepTime * time.Duration(remainingSteps)
	}

	_, _ = fmt.Fprintf(w,
		"\n┌─────────────────────────────────────────────────────────────────────────┐\n")
	_, _ = fmt.Fprintf(w,
		"│ [%3.0f%%] Step %d/%d: %-52s │\n",
		percentage, tp.CompletedSteps, tp.TotalSteps, name)
	_, _ = fmt.Fprintf(w,
		"│ Elapsed: %-17s  Remaining: ~%-22s │\n",
		elapsed.Round(time.Second).String(),
		estimatedRemaining.Round(time.Second).String())
	_, _ = fmt.Fprintf(w,
		"└─────────────────────────────────────────────────────────────────────────┘\n")

	// Return a function to mark step completion
	return func() {
		stepDuration := time.Since(stepStart)
		tp.StepTimes = append(tp.StepTimes, stepDuration)
		_, _ = fmt.Fprintf(w, "  ✓ Completed in %s\n", stepDuration.Round(time.Second))
	}
}

// Complete prints the final summary
func (tp *TestProgress) Complete() {
	w := ginkgo.GinkgoWriter
	total := time.Since(tp.StartTime)
	avgStepTime := total / time.Duration(tp.TotalSteps)

	_, _ = fmt.Fprintf(w, "\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, "  ✓ Completed %s\n", tp.SuiteName)
	_, _ = fmt.Fprintf(w, "───────────────────────────────────────────────────────────────────────────\n")
	_, _ = fmt.Fprintf(w, "  Total Time:      %s\n", total.Round(time.Second))
	_, _ = fmt.Fprintf(w, "  Average/Step:    %s\n", avgStepTime.Round(time.Second))
	_, _ = fmt.Fprintf(w, "  Steps:           %d/%d\n", tp.CompletedSteps, tp.TotalSteps)

	// Show slowest steps
	if len(tp.StepTimes) > 0 {
		_, _ = fmt.Fprintf(w, "───────────────────────────────────────────────────────────────────────────\n")
		_, _ = fmt.Fprintf(w, "  Slowest Steps:\n")

		// Find top 3 slowest steps
		type stepInfo struct {
			index    int
			duration time.Duration
		}
		steps := make([]stepInfo, len(tp.StepTimes))
		for i, d := range tp.StepTimes {
			steps[i] = stepInfo{index: i + 1, duration: d}
		}

		// Simple bubble sort for top 3 (good enough for small n)
		for i := 0; i < len(steps); i++ {
			for j := i + 1; j < len(steps); j++ {
				if steps[j].duration > steps[i].duration {
					steps[i], steps[j] = steps[j], steps[i]
				}
			}
		}

		// Show top 3
		count := 3
		if len(steps) < 3 {
			count = len(steps)
		}
		for i := 0; i < count; i++ {
			_, _ = fmt.Fprintf(w, "    %d. Step %d: %s\n",
				i+1, steps[i].index, steps[i].duration.Round(time.Second))
		}
	}
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════════════\n\n")
}

// Fail marks the progress as failed with an error message
func (tp *TestProgress) Fail(err error) {
	w := ginkgo.GinkgoWriter
	elapsed := time.Since(tp.StartTime)
	_, _ = fmt.Fprintf(w, "\n")
	_, _ = fmt.Fprintf(w, "╔═══════════════════════════════════════════════════════════════════════════╗\n")
	_, _ = fmt.Fprintf(w, "║ ✗ FAILED: %s\n", tp.SuiteName)
	_, _ = fmt.Fprintf(w, "╠═══════════════════════════════════════════════════════════════════════════╣\n")
	_, _ = fmt.Fprintf(w, "║ Failed at step: %d/%d\n", tp.CompletedSteps, tp.TotalSteps)
	_, _ = fmt.Fprintf(w, "║ Time elapsed:   %s\n", elapsed.Round(time.Second))
	_, _ = fmt.Fprintf(w, "║ Error:          %v\n", err)
	_, _ = fmt.Fprintf(w, "╚═══════════════════════════════════════════════════════════════════════════╝\n\n")
}

// SimpleProgress provides a simpler progress indicator for quick operations
type SimpleProgress struct {
	message   string
	startTime time.Time
}

// NewSimpleProgress creates a simple progress indicator
// Usage: progress := NewSimpleProgress("Waiting for pods to be ready")
func NewSimpleProgress(message string) *SimpleProgress {
	sp := &SimpleProgress{
		message:   message,
		startTime: time.Now(),
	}
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "\n⏳ %s...", message)
	return sp
}

// Done marks the simple progress as complete
func (sp *SimpleProgress) Done() {
	duration := time.Since(sp.startTime)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, " ✓ (took %s)\n", duration.Round(time.Second))
}

// DoneWithDetails marks completion with additional details
func (sp *SimpleProgress) DoneWithDetails(details string) {
	duration := time.Since(sp.startTime)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, " ✓ %s (took %s)\n", details, duration.Round(time.Second))
}

// Fail marks the simple progress as failed
func (sp *SimpleProgress) Fail(err error) {
	duration := time.Since(sp.startTime)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, " ✗ Failed after %s: %v\n", duration.Round(time.Second), err)
}
