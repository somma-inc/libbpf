#ifndef _LIBBPF_COMPAT_H_
#define _LIBBPF_COMPAT_H_

#include <string.h>
#include <stdio.h>

static bool is_kprobe_legacy = false;

static int poke_kprobe_events(bool add, const char* name, bool ret) {
	char buf[256];
	int fd, err;
	char *dir;

	fd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND, 0);
	if (fd < 0) {
		err = -errno;
		pr_warn("failed to open kprobe_events file: %d\n", err);
		return err;
	}

	if (ret)
		dir = "kretprobes";
	else
		dir = "kprobes";

	if (add)
		snprintf(buf, sizeof(buf), "%c:%s/%s %s", ret ? 'r' : 'p', dir, name, name);
	else
		snprintf(buf, sizeof(buf), "-:%s/%s", dir, name);

	err = write(fd, buf, strlen(buf));
	if (err < 0) {
		err = -errno;
		pr_warn("failed to %s kprobe '%s': %d\n", add ? "add" : "remove", buf, err);
	}
	close(fd);
	return err >= 0 ? 0 : err;
}

static int add_kprobe_event(const char* func_name, bool is_kretprobe) {
	return poke_kprobe_events(true /*add*/, func_name, is_kretprobe);
}

static int remove_kprobe_event(const char* func_name, bool is_kretprobe) {
	if (is_kprobe_legacy)
		return poke_kprobe_events(false /*remove*/, func_name, is_kretprobe);
	else
		return 0;
}

static int attach_kprobe_legacy(
	struct perf_event_attr *attr,
	const char* func_name,
	bool is_kretprobe) {
	char fname[256];
	int err, id;
	FILE* f = NULL;
	char *dir;

	err = add_kprobe_event(func_name, is_kretprobe);
	if (err) {
		pr_warn("failed to create kprobe event: %d\n", err);
		return -1;
	}

	is_kprobe_legacy = true;

	if (is_kretprobe)
		dir = "kretprobes";
	else
		dir = "kprobes";

	snprintf(fname, sizeof(fname),
	         "/sys/kernel/debug/tracing/events/%s/%s/id", dir, func_name);
	f = fopen(fname, "r");
	if (!f) {
		pr_warn("failed to open kprobe id file '%s': %d\n", fname, -errno);
		goto err_out;
	}

	if (fscanf(f, "%d\n", &id) != 1) {
		pr_warn("failed to read kprobe id from '%s': %d\n", fname, -errno);
		goto err_out;
	}

	fclose(f);

	memset(attr, 0, sizeof(*attr));
	attr->size = sizeof(*attr);
	attr->config = id;
	attr->type = PERF_TYPE_TRACEPOINT;
	attr->sample_period = 1;
	attr->wakeup_events = 1;

	return 0;
err_out:
	if (f)
		fclose(f);
	remove_kprobe_event(func_name, is_kretprobe);
	return -1;
}

static char *kallsyms_fix_symbol(char *section_name)
{
	char addr[17], T, symbol[128], fix[128];
	char *fname = strchr(section_name, '/');
	char *ret = section_name;
	FILE *fp;
	int fname_len, section_len;
	bool found = false;

	if (fname == NULL)
		return ret;

	fname_len = strlen(fname + 1);

	fp = fopen("/proc/kallsyms", "r");

	if (fp == NULL)
		return ret;

	while (fscanf(fp, "%16s %c %127s\n", addr, &T, symbol) != EOF) {
		if (T == 'T' || T == 't') {
			if (strncmp(fname + 1, symbol, fname_len) == 0) {
				if (strncmp(symbol + fname_len, ".isra.", sizeof(".isra.") - 1) == 0) {
					found = true;
					break;
				}
			}
		}
	}

	fclose(fp);

	if (found) {
		section_len = (fname + 1) - section_name;
		memcpy(fix, section_name, section_len);
		snprintf(fix + section_len, sizeof(fix) - section_len, "%s", symbol);
		ret = strdup(fix);
	}

	return ret;
}

#endif
