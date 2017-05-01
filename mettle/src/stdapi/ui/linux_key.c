
#include "tlv.h"

#include <stdio.h>
#include <pthread.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XInput.h>
#include <X11/XKBlib.h>

#define INVALID_EVENT_TYPE  -1

static int key_press_type = INVALID_EVENT_TYPE;
static int key_release_type = INVALID_EVENT_TYPE;

pthread_t pth;
volatile int do_run = 0;

Display * default_display;

void * pthread_run(void * arg)
{
  XEvent e;
  while(do_run) {
    XNextEvent(default_display, &e);                           
    key = (XDeviceKeyEvent *) &e;
    /*fprintf(stderr, "%d", key->state);*/
    /*fprintf(stderr, "s%d", (key->state & ShiftMask));*/
    /*fprintf(stderr, "l%d", (key->state & LockMask));*/
    int state = key->state & (ShiftMask | LockMask)? 1 : 0;
    fprintf(stderr, "%d", state);
    KeySym keySym = XkbKeycodeToKeysym(default_display, key->keycode, 0, key->state & (ShiftMask | LockMask)? 1 : 0);
  }
}
   
struct tlv_packet *stdapi_ui_start_keyscan(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
 
  int i;
  int number = 0; 
  int default_screen;
  FILE * f;
  
  Display * default_display;
  Window root_window;
  XDevice * device;
  XDeviceKeyEvent * key;
  XInputClassInfo       *ip;
  XEventClass           event_list[7];

  default_display = XOpenDisplay(NULL); 
  default_screen = DefaultScreen(default_display);
  root_window = RootWindow(default_display, default_screen);
  device = XOpenDevice(default_display, 11);

  if(!device){
    fprintf(stderr, "unable to open device\n");
  }

  if(device->num_classes > 0) {
    //for (ip = device->classes, i=0; i<info->num_classes; ip++, i++) {
    for(ip = device->classes, i=0; i<1; ++ip, ++i) {
      switch(ip->input_class){
        case KeyClass:
          DeviceKeyPress(device, key_press_type, event_list[number]); number++;
          /*DeviceKeyRelease(device, key_release_type, event_list[number]); number++;*/
          break;
        
        default:
          printf("not key class\n");
          break;
      }
    }
  }
  /* important */
  if(XSelectExtensionEvent(default_display, root_window, event_list, number)) {
    fprintf(stderr, "error selecting extended events\n");
  }

  do_run = 1;
  pthread_create(&pth, NULL, pthread_run, 0);

  return p;
}

struct tlv_packet *stdapi_ui_stop_keyscan(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  XCloseDisplay(default_display);

  do_run = 0;
  /*pthread_join(pth3, NULL);*/

  return p;
}

struct tlv_packet *stdapi_ui_get_keys(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  return p;
}

struct tlv_packet *stdapi_ui_get_keys_utf8(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
  return p;
}
