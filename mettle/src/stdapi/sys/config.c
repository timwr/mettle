/**
 * Copyright 2015 Rapid7
 * @brief System Config API
 * @file config.c
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <dnet.h>
#include <mettle.h>
#include <sigar.h>

#include "log.h"
#include "tlv.h"

static char *normalize_env_var(char *var)
{
	while (*var == '%' || *var == '$') {
		var++;
	}

	char *end = var + strlen(var) - 1;
	while (end > var && *end == '%') {
		end--;
	}

	*(end + 1) = '\0';

	return var;
}

struct tlv_packet *sys_config_getenv(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

	struct tlv_iterator i = {
		.packet = ctx->req,
		.value_type = TLV_TYPE_ENV_VARIABLE,
	};

	char *env_var;
	while ((env_var = tlv_packet_iterate_str(&i))) {
		char *env_val = getenv(normalize_env_var(env_var));
		if (env_val) {
			struct tlv_packet *env = tlv_packet_new(TLV_TYPE_ENV_GROUP, 0);
			env = tlv_packet_add_str(env, TLV_TYPE_ENV_VARIABLE, env_var);
			env = tlv_packet_add_str(env, TLV_TYPE_ENV_VALUE, env_val);
			p = tlv_packet_add_child(p, env);
		}
	}

	return p;
}

struct tlv_packet *sys_config_getuid(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

	return tlv_packet_add_fmt(p, TLV_TYPE_USER_NAME,
			"uid=%d, gid=%d, euid=%d, egid=%d",
			getuid(), geteuid(), getgid(), getegid());
}

struct tlv_packet *sys_config_sysinfo(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;

	sigar_sys_info_t sys_info;
	if (sigar_sys_info_get(mettle_get_sigar(m), &sys_info) == -1) {
		return tlv_packet_response_result(ctx, errno);
	}

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

	p = tlv_packet_add_str(p, TLV_TYPE_COMPUTER_NAME, mettle_get_fqdn(m));
	p = tlv_packet_add_fmt(p, TLV_TYPE_OS_NAME, "%s (%s %s)",
			sys_info.description, sys_info.name, sys_info.version);
	p = tlv_packet_add_str(p, TLV_TYPE_ARCHITECTURE, sys_info.arch);

	return p;
}

void sys_config_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, "stdapi_sys_config_getenv", sys_config_getenv, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_getuid", sys_config_getuid, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_sysinfo", sys_config_sysinfo, m);
}
