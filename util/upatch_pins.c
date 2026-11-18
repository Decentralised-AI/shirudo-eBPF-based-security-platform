// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the pin directory of a loaded upatch holds.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>

#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "paths.h"
#include "upatch_pins.h"

static bool pin_index(const char *entry, const char *prefix, __u32 *out)
{
	__u64 value;

	entry = str_after_prefix(entry, prefix);
	if (!entry)
		return false;
	if (entry[0] == '0' && entry[1])
		return false;
	if (parse_u64(entry, strlen(entry), UINT32_MAX, &value))
		return false;
	*out = (__u32)value;
	return true;
}

int upatch_each_link(const char *name,
		     int (*cb)(__u32 index, const char *pin, void *ctx),
		     void *ctx)
{
	char dir[PATH_MAX], pin[PATH_MAX + NAME_MAX + 2];
	struct dirent *e;
	int ret = 0;
	DIR *d;

	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return -ENAMETOOLONG;
	d = opendir(dir);
	if (!d)
		return -errno;
	while (!ret && (e = readdir(d))) {
		__u32 index;

		if (!pin_index(e->d_name, LINK_PIN_PREFIX, &index))
			continue;
		if (strsprintf(pin, sizeof(pin), "%s/%s", dir, e->d_name) < 0)
			ret = -ENAMETOOLONG;
		else
			ret = cb(index, pin, ctx);
	}
	closedir(d);
	return ret;
}

int upatch_xdp_prog_pin(char *out, size_t cap, const char *name, __u32 index)
{
	char entry[32];

	if (strsprintf(entry, sizeof(entry), XDP_PROG_PIN_PREFIX "%u", index) < 0 ||
	    upatch_pin_path(out, cap, name,
			    (const char *const[]){ entry, NULL }))
		return -ENAMETOOLONG;
	return 0;
}

int upatch_xdp_prog_open(const char *name, __u32 index, __u32 *id)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	char pin[PATH_MAX];
	int fd, ret;

	if (upatch_xdp_prog_pin(pin, sizeof(pin), name, index))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	ret = bpf_prog_get_info_by_fd(fd, &info, &len);
	if (!ret && info.type != BPF_PROG_TYPE_XDP)
		ret = -ESTALE;
	if (ret) {
		close(fd);
		return ret;
	}
	*id = info.id;
	return fd;
}

int upatch_pin_payload(const char *name, __u8 out[UPATCH_PAYLOAD_HASH_LEN])
{
	char dir[PATH_MAX];
	ssize_t n;

	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return -ENAMETOOLONG;
	n = getxattr(dir, XATTR_PAYLOAD, out, UPATCH_PAYLOAD_HASH_LEN);
	if (n < 0)
		return -errno;
	return n == UPATCH_PAYLOAD_HASH_LEN ? 0 : -EINVAL;
}

int upatch_each_pinned(int (*cb)(const char *name, void *ctx), void *ctx)
{
	struct dirent *e;
	int ret = 0;
	DIR *d;

	d = opendir(BPFFS_UPATCHES_DIR);
	if (!d)
		return errno == ENOENT ? 0 : -errno;
	while (!ret && (e = readdir(d))) {
		char name[UPATCH_NAME_MAX + 1];

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") ||
		    upatch_name_from_bpffs(name, sizeof(name), e->d_name))
			continue;
		ret = cb(name, ctx);
	}
	closedir(d);
	return ret;
}
