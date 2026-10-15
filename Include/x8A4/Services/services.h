//
// Created by cryptic on 4/14/24.
//

/**
 * @file services.h
 * @author Cryptiiiic
 * @brief This file is the header file for services.c
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_SERVICES_H
#define X8A4_SERVICES_H

/* Include headers */
#include <x8A4/Registry/registry.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>

/* Typedefs */
typedef io_object_t io_service_t;

/* External prototypes */
io_service_t IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);
CFMutableDictionaryRef IOServiceMatching(const char *);

/* Prototypes */
io_service_t get_io_aes_accel_service(void);

/* Cached Variables */
extern io_service_t io_aes_accel_service_cached;

#endif//X8A4_SERVICES_H
