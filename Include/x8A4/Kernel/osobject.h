//
// Created by cryptic on 12/19/24.
//

/**
 * @file osobject.h
 * @author Cryptiiiic
 * @brief This file is the header file for osobject.c
 * @version 1.0.1
 * @date 2024-12-19
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_OSOBJECT_H
#define X8A4_OSOBJECT_H

/* Include headers */
#include <stdint.h>

/* Enum Variables */
enum os_type {
  OS_DATA,
  OS_STRING,
};

/* Structure Variables */
struct os_dict_entry {
  uint64_t key;
  uint64_t val;
};

/* Prototypes */
uint64_t os_object_cast(uint64_t object, enum os_type type);
uint32_t get_os_metabase_size(uint64_t object);
uint64_t get_os_dict_from_os_object(uint64_t os_object);
uint32_t get_os_dict_size(uint64_t dict);
uint32_t extract_os_size(uint32_t *size);
uint64_t get_entry_from_os_dict(uint64_t dict, enum os_type entry_type, const char *entry_key, uint32_t *out_size);
int os_dict_contains_key(uint64_t dict, const char *entry_key);

#endif // X8A4_OSOBJECT_H
