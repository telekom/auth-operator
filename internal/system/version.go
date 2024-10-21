package system

import "fmt"

var Name = "authn-authz-operator"
var Version = "<unset>"
var Commit = "<unset>"
var Repository = "https://gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator"

func PrettyInfo() string {
	return fmt.Sprintf(`
===========================================================================
Application: %s
Version %s
GOTO: %s/-/tree/%s
===========================================================================
`, Name, Version, Repository, Commit)
}
