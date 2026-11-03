/*
 * local_ports: keeps the listed TCP ports reachable from this device only.
 *
 * A UserLAnd session's SSH and VNC servers listen on every interface, which puts them on the
 * local network whenever the device is on Wi-Fi. Unless the user asked for that -- a "Remote"
 * session, meant to be reached from another device -- they should answer on loopback alone.
 * The servers come from the distribution images and are started by the images' own scripts,
 * so rather than changing every image (and every filesystem already extracted from one), this
 * rewrites their bind() calls: a bind of one of the listed ports to any non-loopback address
 * becomes a bind to loopback.
 *
 * IPv6 binds go to the IPv4-mapped loopback address (::ffff:127.0.0.1), not ::1. A dual-stack
 * socket bound there still accepts the 127.0.0.1 connections UserLAnd's own clients make,
 * where ::1 would refuse them; a v6-only socket can't bind it and fails, which only costs a
 * server its IPv6 listener -- the servers UserLAnd runs listen on IPv4 too.
 *
 * Every other port is left alone, so a server the user runs on purpose stays reachable.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <talloc.h>

#include "cli/note.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "extension/extension.h"

#define MAX_PORTS 16

typedef struct {
	size_t count;
	uint16_t ports[MAX_PORTS];
} Config;

/* Parses "2022,5951,..." into @config; false if it isn't a list of ports. */
static bool parse_ports(Config *config, const char *value)
{
	const char *cursor = value;

	config->count = 0;
	while (cursor != NULL && *cursor != '\0') {
		char *end;
		long port = strtol(cursor, &end, 10);

		if (end == cursor || port <= 0 || port > 65535 || config->count == MAX_PORTS)
			return false;
		config->ports[config->count++] = (uint16_t) port;
		if (*end == '\0')
			break;
		if (*end != ',')
			return false;
		cursor = end + 1;
	}
	return config->count > 0;
}

static bool listed(const Config *config, uint16_t port)
{
	size_t i;

	for (i = 0; i < config->count; i++) {
		if (config->ports[i] == port)
			return true;
	}
	return false;
}

/* Rewrites a bind() of a listed port to a non-loopback address; see the header. */
static void handle_bind(Tracee *tracee, const Config *config)
{
	struct sockaddr_storage address;
	word_t length = peek_reg(tracee, CURRENT, SYSARG_3);
	word_t replacement;

	if (length < sizeof(sa_family_t) || length > sizeof(address))
		return;
	memset(&address, 0, sizeof(address));
	if (read_data(tracee, &address, peek_reg(tracee, CURRENT, SYSARG_2), length) < 0)
		return;

	if (address.ss_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
		struct sockaddr_in *in = (struct sockaddr_in *) &address;

		if (!listed(config, ntohs(in->sin_port)))
			return;
		if ((ntohl(in->sin_addr.s_addr) >> 24) == 127)
			return;
		in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else if (address.ss_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &address;
		const uint8_t *bytes = in6->sin6_addr.s6_addr;

		if (!listed(config, ntohs(in6->sin6_port)))
			return;
		if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr))
			return;
		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr) && bytes[12] == 127)
			return;
		memset(&in6->sin6_addr, 0, sizeof(in6->sin6_addr));
		in6->sin6_addr.s6_addr[10] = 0xff;
		in6->sin6_addr.s6_addr[11] = 0xff;
		in6->sin6_addr.s6_addr[12] = 127;
		in6->sin6_addr.s6_addr[15] = 1;
	} else {
		return;
	}

	/* A copy rather than an edit in place: the tracee's own struct stays as it wrote it. */
	replacement = alloc_mem(tracee, length);
	if (replacement == 0 || write_data(tracee, replacement, &address, length) < 0)
		return;
	poke_reg(tracee, SYSARG_2, replacement);
	VERBOSE(tracee, 2, "local_ports: bind kept to loopback");
}

int local_ports_callback(Extension *extension, ExtensionEvent event,
	intptr_t data1, intptr_t data2 UNUSED)
{
	switch (event) {
	case INITIALIZATION: {
		static FilteredSysnum filtered_sysnums[] = {
			{ PR_bind, 0 },
			FILTERED_SYSNUM_END,
		};
		Config *config = talloc_zero(extension, Config);

		if (config == NULL)
			return -ENOMEM;
		if (!parse_ports(config, (const char *) data1)) {
			note(TRACEE(extension), ERROR, USER,
				"--local-ports expects a comma-separated list of ports, e.g. 2022,5951");
			return -EINVAL;
		}
		extension->config = config;
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	/* One list for the whole session. */
	case INHERIT_PARENT:
		return 0;

	case SYSCALL_ENTER_END:
		if (get_sysnum(TRACEE(extension), ORIGINAL) == PR_bind)
			handle_bind(TRACEE(extension), extension->config);
		return 0;

	default:
		return 0;
	}
}
