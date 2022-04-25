// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"context"

	"github.com/sylabs/sif/v2/pkg/user"
)

// Unmounts the filesystem at mountPath.
func (a *App) Unmount(ctx context.Context, mountPath string) error {
	return user.Unmount(ctx, mountPath,
		user.OptUnmountStdout(a.opts.out),
		user.OptUnmountStderr(a.opts.err),
	)
}
