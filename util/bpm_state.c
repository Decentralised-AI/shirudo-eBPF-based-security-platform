// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm_state.h"
#include "io.h"
#include "json.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

#define STATE_FILE_MAX	(8u * 1024u * 1024u)
#define STATE_EMIT_MAX	(1024u * 1024u)

struct state_sink {
	struct bpm_state_entry *items;
	int n;
	struct bpm_state_entry scratch;
};

static int on_state_entry(void *ud)
{
	struct state_sink *s = ud;
	char expected[PATH_MAX];

	if (s->n >= BPM_MAX_STATE)
		return -E2BIG;
	if (!s->scratch.name[0] || !s->scratch.version[0] ||
	    !bpm_name_ok(s->scratch.name) ||
	    !bpm_version_ok(s->scratch.version) ||
	    !bpm_name_ok(s->scratch.source))
		return -EINVAL;
	if (strsprintf(expected, sizeof(expected), "%s/%s/%s",
		       BPM_PACKAGES_DIR, s->scratch.name,
		       s->scratch.version) < 0 ||
	    strcmp(expected, s->scratch.path))
		return -EINVAL;
	s->items[s->n++] = s->scratch;
	/* A field the next entry leaves out is not this entry's. */
	memset(&s->scratch, 0, sizeof(s->scratch));
	return 0;
}

int bpm_state_parse(const char *body, size_t len,
		    struct bpm_state_entry *st, int *n)
{
	struct state_sink sink = { .items = st };
	struct json_array arr = { on_state_entry, &sink };
	struct json_field sub[] = {
		{ "name", JSON_T_STRING, sink.scratch.name,
		  sizeof(sink.scratch.name), 0, NULL, 0 },
		{ "version", JSON_T_STRING, sink.scratch.version,
		  sizeof(sink.scratch.version), 0, NULL, 0 },
		{ "source", JSON_T_STRING, sink.scratch.source,
		  sizeof(sink.scratch.source), 0, NULL, 0 },
		{ "path", JSON_T_STRING, sink.scratch.path,
		  sizeof(sink.scratch.path), 0, NULL, 0 },
	};
	struct json_field root[] = {
		{ "packages", JSON_T_ARRAY, &arr, 0, 0, sub, ARRAY_SIZE(sub) },
	};
	int ret;

	ret = json_parse(body, len, root, ARRAY_SIZE(root));
	if (ret)
		return ret;
	if (!root[0].seen)
		return -EINVAL;
	*n = sink.n;
	return 0;
}

int bpm_state_emit(const struct bpm_state_entry *st, int n, char *buf,
		   size_t cap, size_t *len)
{
	struct json_emit e = { .buf = buf, .cap = cap };

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_arr_open(&e, "packages");
	for (int i = 0; i < n; i++) {
		json_obj_open(&e);
		json_kv_string(&e, "name", st[i].name);
		json_kv_string(&e, "version", st[i].version);
		json_kv_string(&e, "source", st[i].source);
		json_kv_string(&e, "path", st[i].path);
		json_obj_close(&e);
	}
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err)
		return -E2BIG;
	*len = e.len;
	return 0;
}

int bpm_state_read(struct bpm_state_entry *st, int *n)
{
	size_t len;
	char *body;
	int ret;

	ret = read_file(BPM_STATE_PATH, STATE_FILE_MAX, &body, &len);
	if (ret == -ENOENT) {
		*n = 0;
		return 0;
	}
	if (ret)
		return ret;
	ret = bpm_state_parse(body, len, st, n);
	xfree(body, len + 1);
	return ret;
}

int bpm_state_write(const struct bpm_state_entry *st, int n, bool *published)
{
	size_t len = 0;
	char *buf;
	int ret;

	if (published)
		*published = false;
	buf = xmalloc(STATE_EMIT_MAX);
	if (!buf)
		return -ENOMEM;
	ret = bpm_state_emit(st, n, buf, STATE_EMIT_MAX, &len);
	if (!ret)
		ret = seal_mkdir_p(BPM_VAR_DIR, 0700);
	if (!ret)
		ret = seal_write_file_status(BPM_STATE_PATH, buf, len, 0600,
					     published);
	xfree(buf, STATE_EMIT_MAX);
	return ret;
}
