package main 

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestResolverWithDig(t *testing.T) {
	go startUDPServer(":8080")

	time.Sleep(300 * time.Millisecond)

	domains := []string{
		"google.com",
		"github.com",
		"kernel.org",
		"wikipedia.org",
		"cloudflare.com",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {

			cmd := exec.Command(
				"dig",
				"@127.0.0.1",
				"-p", "8080",
				domain,
			)

			output, err := cmd.CombinedOutput()

			if err != nil {
				t.Fatalf(
					"dig failed for %s: %v\n%s",
					domain,
					err,
					output,
				)
			}

			out := string(output)

			if !strings.Contains(out, "status: NOERROR") {
				t.Fatalf(
					"expected NOERROR for %s\n%s",
					domain,
					out,
				)
			}

			if !strings.Contains(out, "ANSWER SECTION") {
				t.Fatalf(
					"expected ANSWER SECTION for %s\n%s",
					domain,
					out,
				)
			}
		})
	}
}
