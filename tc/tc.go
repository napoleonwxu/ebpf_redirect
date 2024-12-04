package tc

import (
	"fmt"

	"github.com/florianl/go-tc"
)

func withTc(handler func(rtnl *tc.Tc) error) error {
	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("failed to open tc rtnetlink: %w", err)
	}
	defer rtnl.Close()

	return handler(rtnl)
}
