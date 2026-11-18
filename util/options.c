// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The one parser of command line options, and the rules it holds every
 * command to.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "help.h"
#include "log.h"
#include "options.h"
#include "similar.h"

void opt_usage(const struct opt_parser *p, const char *fmt, ...)
{
	char msg[512];
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vstrsprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	pr_err("%s: %s", p->command, ret < 0 ? fmt : msg);
}
