//
// Created by cryptic on 4/14/24.
//

/**
 * @file slide.c
 * @author Cryptiiiic
 * @brief This file is for all kernel slide related code.
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <stdint.h>
#include <x8A4/Kernel/slide.h>
#include <x8A4/Kernel/kernel.h>
#include <x8A4/Kernel/kpf.h>
#include <x8A4/Logger/logger.h>
#include <x8A4/x8A4.h>
#include <x8A4_state.h>

/* Cached Variables */
uint64_t slide_cached = 0;

/* Functions */
/**
 * @brief           Get kaslr slide
 * @return          Kaslr slide
 */
uint64_t get_slide(void) {
  uint64_t slide = slide_cached;
  if (slide) {
    return slide;
  }
  if (!gXPF.kernelIsArm64e) {
    slide = palera1n_get_slide();
    if (slide) {
      slide_cached = slide;
      return slide;
    }
  }
  slide = krw_get_kbase();
  if (slide) {
    slide -= gXPF.kernelBase;
    slide_cached = slide;
    return slide;
  }
  x8A4_log_error("Kernel slide is zero!\n", "");
  return 0;
}

/**
 * @brief           Get kaslr slide from palera1n ramdisk
 * @return          Kaslr slide
 */
uint64_t palera1n_get_slide(void) {
  uint64_t slide = 0;
  int rmd0 = open("/dev/rmd0", O_RDONLY, 0);
  if (rmd0 < 0) {
    x8A4_log_error("Could not get paleinfo! (%d:%s:%d:%s)\n", rmd0, strerror(rmd0), errno, strerror(errno));
    return 0;
  }
  uint64_t off = lseek(rmd0, 0, SEEK_SET);
  if (off == -1) {
    x8A4_log_error("Failed to lseek ramdisk to 0\n", "");
    close(rmd0);
    return 0;
  }
  uint32_t pinfo_off;
  ssize_t didRead = read(rmd0, &pinfo_off, sizeof(uint32_t));
  if (didRead != (ssize_t)sizeof(uint32_t)) {
    x8A4_log_error("Read %ld bytes does not match expected %lu bytes\n", didRead, sizeof(uint32_t));
    close(rmd0);
    return 0;
  }
  off = lseek(rmd0, pinfo_off, SEEK_SET);
  if (off != pinfo_off) {
    x8A4_log_error("Failed to lseek ramdisk to %u\n", pinfo_off);
    close(rmd0);
    return 0;
  }
  struct paleinfo {
    uint32_t magic; /* 'PLSH' */
    uint32_t version; /* 2 */
    uint64_t kbase; /* kernel base */
    uint64_t kslide; /* kernel slide */
    uint64_t flags; /* unified palera1n flags */
    char rootdev[0x10]; /* ex. disk0s1s8 */
                        /* int8_t loglevel; */
  } __attribute__((packed));
  struct paleinfo_legacy {
    uint32_t magic;   // 'PLSH' / 0x504c5348
    uint32_t version; // 1
    uint32_t flags;
    char rootdev[0x10];
  };
  struct paleinfo *pinfo_p = (struct paleinfo *)calloc(1, sizeof(struct paleinfo));
  struct paleinfo_legacy *pinfo_legacy_p = NULL;
  didRead = read(rmd0, pinfo_p, sizeof(struct paleinfo));
  if (didRead != (ssize_t)sizeof(struct paleinfo)) {
    x8A4_log_error("Read %ld bytes does not match expected %lu bytes\n", didRead, sizeof(struct paleinfo));
    close(rmd0);
    free(pinfo_p);
    return 0;
  }
  if (pinfo_p->magic != 'PLSH') {
    close(rmd0);
    pinfo_off += 0x1000;
    pinfo_legacy_p = (struct paleinfo_legacy *)calloc(1, sizeof(struct paleinfo_legacy));
    didRead = read(rmd0, pinfo_legacy_p, sizeof(struct paleinfo_legacy));
    if (didRead != (ssize_t)sizeof(struct paleinfo_legacy)) {
      x8A4_log_error("Read %ld bytes does not match expected %lu bytes\n", didRead, sizeof(struct paleinfo_legacy));
      close(rmd0);
      free(pinfo_p);
      free(pinfo_legacy_p);
      return 0;
    }
    if(verbose_cached) {
      x8A4_log_debug("pinfo_legacy_p->magic: %s\n", (char *)&pinfo_legacy_p->magic);
      x8A4_log_debug("pinfo_legacy_p->magic: 0x%X\n", pinfo_legacy_p->magic);
      x8A4_log_debug("pinfo_legacy_p->version: 0x%Xd\n", pinfo_legacy_p->version);
      x8A4_log_debug("pinfo_legacy_p->flags: 0x%X\n", pinfo_legacy_p->flags);
      x8A4_log_debug("pinfo_legacy_p->rootdev: %s\n", pinfo_legacy_p->rootdev);
    }
    if (pinfo_legacy_p->magic != 'PLSH') {
      x8A4_log_error("Detected corrupted paleinfo!\n", "");
      close(rmd0);
      free(pinfo_p);
      free(pinfo_legacy_p);
      return 0;
    }
    if (pinfo_legacy_p->version != 1U) {
      x8A4_log_error("Unexpected paleinfo version: %u, expected %u\n", pinfo_legacy_p->version, 1U);
      close(rmd0);
      free(pinfo_p);
      free(pinfo_legacy_p);
      return 0;
    }
    lseek(rmd0, pinfo_off - 0x1000, SEEK_SET);
    struct kerninfo {
      uint64_t size;
      uint64_t base;
      uint64_t slide;
      uint32_t flags;
    };
    struct kerninfo *kerninfo_p = malloc(sizeof(struct kerninfo));
    read(rmd0, kerninfo_p, sizeof(struct kerninfo));
    close(rmd0);
    slide = kerninfo_p->slide;
    free(kerninfo_p);
  } else {
    if(verbose_cached) {
      x8A4_log_debug("pinfo_p->magic: %s\n", (const char *)&pinfo_p->magic);
      x8A4_log_debug("pinfo_p->magic: 0x%X\n", pinfo_p->magic);
      x8A4_log_debug("pinfo_p->version: 0x%Xd\n", pinfo_p->version);
      x8A4_log_debug("pinfo_p->kbase: 0x%llX\n", pinfo_p->kbase);
      x8A4_log_debug("pinfo_p->kslide: 0x%llX\n", pinfo_p->kslide);
      x8A4_log_debug("pinfo_p->flags: 0x%llX\n", pinfo_p->flags);
      x8A4_log_debug("pinfo_p->rootdev: %s\n", pinfo_p->rootdev);
      slide = pinfo_p->kslide;
    }
  }
  free(pinfo_p);
  free(pinfo_legacy_p);
  return slide;
}
