/**
 * Copyright 2015 Rapid7
 * @brief UI API
 * @file ui.c
 */

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <mettle.h>

#include "channel.h"
#include "log.h"
#include "tlv.h"

#if HAVE_SCREENSHOT
extern struct tlv_packet *stdapi_ui_desktop_screenshot(struct tlv_handler_ctx *ctx);
#endif

void ui_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

#if HAVE_SCREENSHOT
	tlv_dispatcher_add_handler(td, "stdapi_ui_desktop_screenshot", stdapi_ui_desktop_screenshot, m);
#endif
}

