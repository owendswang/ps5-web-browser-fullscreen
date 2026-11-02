/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once
#include <sys/types.h>

/* Native layouts are checked before selecting or restoring device density. */
int browser_density_check(pid_t pid, unsigned density);
/* The caller owns the ptrace attachment, confirms the stop and always detaches. */
int browser_density_apply_stopped(pid_t pid, unsigned density);
