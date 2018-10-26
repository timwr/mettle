#import <AVFoundation/AVFoundation.h>

#if TARGET_OS_IPHONE
#import <UIKit/UIImage.h>

//extern "C" CGImageRef UIGetScreenImage();

//OBJC_EXTERN CGImageRef UIGetScreenImage(void);
OBJC_EXTERN UIImage* _UICreateScreenUIImage(void) NS_RETURNS_RETAINED;

#endif


#include "tlv.h"
#include "ui.h"


struct tlv_packet *desktop_screenshot(struct tlv_handler_ctx *ctx)
{
  struct tlv_packet *p;
  uint32_t quality = 0;
  tlv_packet_get_u32(ctx->req, TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY, &quality);
  float compression = quality / 100;
  @autoreleasepool {

#if TARGET_OS_IPHONE
    //CGImageRef image = _UICreateScreenUIImage();
    //CGImageRef image = UICreateScreenUIImage();
    //CGImageRef image = UIGetScreenImage();

    //CGImageRef screen = UIGetScreenImage();
    //UIImage *image = [UIImage imageWithCGImage:screen];
    //CFRelease(screen);

    UIImage *image = _UICreateScreenUIImage();
    NSData *newImage = UIImageJPEGRepresentation(image, 1.0);
    //NSData *newImage = (__bridge NSData *)newImageData;
    p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    p = tlv_packet_add_raw(p, TLV_TYPE_DESKTOP_SCREENSHOT, newImage.bytes, newImage.length);
#else
    CGImageRef image = CGDisplayCreateImage(kCGDirectMainDisplay);

    CFMutableDataRef newImageData = CFDataCreateMutable(NULL, 0);
    CGImageDestinationRef destination = CGImageDestinationCreateWithData(newImageData, kUTTypeJPEG, 1, NULL);
    float compression = quality / 100;
    NSDictionary *properties = [NSDictionary dictionaryWithObjectsAndKeys:
                                @(compression), kCGImageDestinationLossyCompressionQuality,
                                nil];
    CGImageDestinationAddImage(destination, image, (__bridge CFDictionaryRef)properties);
    if (CGImageDestinationFinalize(destination)) {
      NSData *newImage = (__bridge NSData *)newImageData;
      p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
      p = tlv_packet_add_raw(p, TLV_TYPE_DESKTOP_SCREENSHOT, newImage.bytes, newImage.length);
    } else {
      p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    }
#endif
  }
  return p;
}
