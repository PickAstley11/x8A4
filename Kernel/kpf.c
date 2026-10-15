//
// Created by cryptic on 4/27/24.
//

/**
 * @file kpf.c
 * @author Cryptiiiic
 * @brief This file is for all kernel kpf related code.
 * @version 1.0.1
 * @date 2024-04-27
 *
 * @copyright Copyright (c) 2024
 */

/* Include Headers */
#include <x8A4/Kernel/nvram.h>
#include <x8A4/Kernel/kpf.h>
#include <x8A4/Logger/logger.h>
#include <x8A4/x8A4.h>
#include <x8A4_state.h>

/* Variables */
PFSection *apple_image4_fileset_sections[3] = {0};

/* Cached Variables */
uint64_t kpf_nonce_domains_cached = 0;
int kpf_nonce_domains_length_cached = 0;

/* Functions */
/**
 * @brief           Sets up XPF fileset kernel sections for the IMG4 Kext
 * @return          Zero on success
 */
int xpf_setup_fileset_sections(void) {
  if (gXPF.kernelIsFileset &&
      !(apple_image4_fileset_sections[0] && apple_image4_fileset_sections[1] &&
        apple_image4_fileset_sections[2])) {
    apple_image4_fileset_sections[0] = xpf_pfsec_init("com.apple.security.AppleImage4", "__TEXT_EXEC", "__text");
    apple_image4_fileset_sections[1] = xpf_pfsec_init("com.apple.security.AppleImage4", "__DATA_CONST", "__const");
    apple_image4_fileset_sections[2] = xpf_pfsec_init("com.apple.security.AppleImage4", "__TEXT", "__cstring");
    return (apple_image4_fileset_sections[0] &&
            apple_image4_fileset_sections[1] &&
            apple_image4_fileset_sections[2])
               ? 0
               : -1;
  }
  return 0;
}

/**
 * @brief           Frees XPF fileset kernel sections for the IMG4 Kext
 */
void xpf_free_fileset_sections(void) {
  if (gXPF.kernelIsFileset) {
    if (apple_image4_fileset_sections[0])
      pfsec_free(apple_image4_fileset_sections[0]);
    if (apple_image4_fileset_sections[1])
      pfsec_free(apple_image4_fileset_sections[1]);
    if (apple_image4_fileset_sections[2])
      pfsec_free(apple_image4_fileset_sections[2]);
  }
}


/**
 * @brief           XPF Kernel patchfind the nonce slots array
 * @return          Address of nonce slots array
 */
uint64_t xpf_find_nonce_slots_array(void) {
  if(strcmp(gXPF.darwinVersion, "23.0.0") < 0 && !nonce_slot_format_cached) {
    return 0;
  }
  PFSection *kernel_security_appleimage4_text_section = NULL;
  PFSection *kernel_security_appleimage4_dataconst_section = NULL;
  PFSection *kernel_security_appleimage4_string_section = NULL;
  if (gXPF.kernelIsFileset) {
    if (xpf_setup_fileset_sections()) {
      return 0;
    }
    kernel_security_appleimage4_text_section = apple_image4_fileset_sections[0];
    kernel_security_appleimage4_dataconst_section = apple_image4_fileset_sections[1];
    kernel_security_appleimage4_string_section = apple_image4_fileset_sections[2];
  } else {
    if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
      kernel_security_appleimage4_text_section = gXPF.kernelPLKTextSection;
      kernel_security_appleimage4_dataconst_section = gXPF.kernelPLKTextSection;
      kernel_security_appleimage4_string_section =
          gXPF.kernelPrelinkTextSection;
    } else {
      kernel_security_appleimage4_text_section = gXPF.kernelTextSection;
      kernel_security_appleimage4_dataconst_section = gXPF.kernelTextSection;
      kernel_security_appleimage4_string_section = gXPF.kernelStringSection;
    }
  }
  if (!kernel_security_appleimage4_text_section ||
      !kernel_security_appleimage4_dataconst_section ||
      !kernel_security_appleimage4_string_section) {
    x8A4_log_error("Failed to setup kernel sections!\n", "");
    return 0;
  }
  if (kpf_nonce_domains_cached) {
    return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(
        kernel_security_appleimage4_text_section, kpf_nonce_domains_cached + 4);
  }
  PFStringMetric *krn_metric =
      pfmetric_string_init(kAppleSystemVarGUID"krn.");
  if (!krn_metric) {
    x8A4_log_error("Failed to pfmetric_string_init for \""kAppleSystemVarGUID"krn.""\" string!\n", "");
    return 0;
  }
  __block uint64_t krn_addr = 0;
  pfmetric_run(kernel_security_appleimage4_string_section, krn_metric,
               ^(uint64_t vmaddr, bool *stop) {
                 krn_addr = vmaddr;
                 *stop = true;
               });
  pfmetric_free(krn_metric);
  if (!krn_addr) {
    x8A4_log_error("Failed to find \""kAppleSystemVarGUID"krn.""\" string!\n", "");
    return 0;
  }
  PFXrefMetric *krn_xref_metric =
      pfmetric_xref_init(krn_addr, XREF_TYPE_MASK_REFERENCE);
  __block uint64_t krn_ref = 0;
  pfmetric_run(kernel_security_appleimage4_text_section,
               krn_xref_metric, ^(uint64_t vmaddr, bool *stop) {
                 krn_ref = vmaddr;
                 *stop = true;
               });
  pfmetric_free(krn_xref_metric);
  if (!krn_ref) {
    x8A4_log_error("Failed to find \""kAppleSystemVarGUID"krn.""\" string reference!\n", "");
    return 0;
  }
  uint32_t adrp_any_inst = 0, adrp_any_mask = 0;
  arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE,
                  ARM64_REG_ANY, &adrp_any_inst, &adrp_any_mask);
  uint64_t prev_adrp_addr = pfsec_find_prev_inst(
      kernel_security_appleimage4_text_section, krn_ref - 8, 20,
      adrp_any_inst, adrp_any_mask);
  if (!prev_adrp_addr) {
    x8A4_log_error("Failed to find previous adrp in darwin_el2_init function!\n", "");
    return 0;
  }
  uint64_t nonce_domains = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(
      kernel_security_appleimage4_text_section, prev_adrp_addr + 4);
  if (!nonce_domains) {
    x8A4_log_error("Failed to find nonce domains array!\n", "");
    return 0;
  }
  kpf_nonce_domains_cached = prev_adrp_addr;
  return nonce_domains;
}

/**
 * @brief           XPF Kernel patchfind the nonce domains array
 * @return          Address of nonce domains array
 */
uint64_t xpf_find_nonce_domains_array(void) {
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
    return xpf_find_nonce_slots_array();
  }
  PFSection *kernel_security_appleimage4_text_section = NULL;
  PFSection *kernel_security_appleimage4_dataconst_section = NULL;
  PFSection *kernel_security_appleimage4_string_section = NULL;
  if (gXPF.kernelIsFileset) {
    if (xpf_setup_fileset_sections()) {
      return 0;
    }
    kernel_security_appleimage4_text_section = apple_image4_fileset_sections[0];
    kernel_security_appleimage4_dataconst_section = apple_image4_fileset_sections[1];
    kernel_security_appleimage4_string_section = apple_image4_fileset_sections[2];
  } else {
    if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
      kernel_security_appleimage4_text_section = gXPF.kernelPLKTextSection;
      kernel_security_appleimage4_dataconst_section = gXPF.kernelPLKTextSection;
      kernel_security_appleimage4_string_section =
          gXPF.kernelPrelinkTextSection;
    } else {
      kernel_security_appleimage4_text_section = gXPF.kernelTextSection;
      kernel_security_appleimage4_dataconst_section = gXPF.kernelTextSection;
      kernel_security_appleimage4_string_section = gXPF.kernelStringSection;
    }
  }
  if (!kernel_security_appleimage4_text_section ||
      !kernel_security_appleimage4_dataconst_section ||
      !kernel_security_appleimage4_string_section) {
    x8A4_log_error("Failed to setup kernel sections!\n", "");
    return 0;
  }
  if (kpf_nonce_domains_cached) {
    return kpf_nonce_domains_cached;
//    return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(
//        kernel_security_appleimage4_text_section, kpf_nonce_domains_cached + 4);
  }
  PFStringMetric *nonce_domain_metric =
      pfmetric_string_init("invalid nonce domain: %llu");
  if (!nonce_domain_metric) {
    x8A4_log_error("Failed to pfmetric_string_init for nonce domain string!\n", "");
    return 0;
  }
  __block uint64_t nonce_domain_addr = 0;
  pfmetric_run(kernel_security_appleimage4_string_section, nonce_domain_metric,
               ^(uint64_t vmaddr, bool *stop) {
                 nonce_domain_addr = vmaddr;
                 *stop = true;
               });
  pfmetric_free(nonce_domain_metric);
  if (!nonce_domain_addr) {
    x8A4_log_debug_error("Failed to find nonce domain string!\n", "");
    return 0;
  }
  PFXrefMetric *nonce_domain_xref_metric =
      pfmetric_xref_init(nonce_domain_addr, XREF_TYPE_MASK_REFERENCE);
  __block uint64_t nonce_domain_ref = 0;
  pfmetric_run(kernel_security_appleimage4_text_section,
               nonce_domain_xref_metric, ^(uint64_t vmaddr, bool *stop) {
                 nonce_domain_ref = vmaddr;
                 *stop = true;
               });
  pfmetric_free(nonce_domain_xref_metric);
  if (!nonce_domain_ref) {
    x8A4_log_error("Failed to find nonce domain string reference!\n", "");
    return 0;
  }
  uint32_t adrp_any_inst = 0, adrp_any_mask = 0;
  arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE,
                  ARM64_REG_ANY, &adrp_any_inst, &adrp_any_mask);
  uint64_t prev_adrp_addr = pfsec_find_prev_inst(
      kernel_security_appleimage4_text_section, nonce_domain_ref - 8, 20,
      adrp_any_inst, adrp_any_mask);
  if (!prev_adrp_addr) {
    x8A4_log_error("Failed to find previous adrp in img4_nonce_domain_at function!\n", "");
    return 0;
  }
  uint64_t nonce_domains = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(
      kernel_security_appleimage4_text_section, prev_adrp_addr + 4);
  if (!nonce_domains) {
    x8A4_log_error("Failed to find nonce domains array!\n", "");
    return 0;
  }
  kpf_nonce_domains_cached = nonce_domains;
  return nonce_domains;
}

/**
 * @brief           XPF Kernel patchfind the nonce slots array length
 * @return          Length of the nonce domains array
 */
int xpf_find_nonce_slots_array_length(void) {
  if(strcmp(gXPF.darwinVersion, "23.0.0") < 0 && !nonce_slot_format_cached) {
    return 0;
  }
  PFSection *kernel_security_appleimage4_text_section = NULL;
  PFSection *kernel_security_appleimage4_dataconst_section = NULL;
  PFSection *kernel_security_appleimage4_string_section = NULL;
  if (gXPF.kernelIsFileset) {
    if (xpf_setup_fileset_sections()) {
      return 0;
    }
    kernel_security_appleimage4_text_section = apple_image4_fileset_sections[0];
    kernel_security_appleimage4_dataconst_section = apple_image4_fileset_sections[1];
    kernel_security_appleimage4_string_section = apple_image4_fileset_sections[2];
  } else {
    if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
      kernel_security_appleimage4_text_section = gXPF.kernelPLKTextSection;
      kernel_security_appleimage4_dataconst_section = gXPF.kernelPLKTextSection;
      kernel_security_appleimage4_string_section =
          gXPF.kernelPrelinkTextSection;
    } else {
      kernel_security_appleimage4_text_section = gXPF.kernelTextSection;
      kernel_security_appleimage4_dataconst_section = gXPF.kernelTextSection;
      kernel_security_appleimage4_string_section = gXPF.kernelStringSection;
    }
  }
  if (!kernel_security_appleimage4_text_section ||
      !kernel_security_appleimage4_dataconst_section ||
      !kernel_security_appleimage4_string_section) {
    x8A4_log_error("Failed to setup kernel sections!\n", "");
    return 0;
  }
  if(kpf_nonce_domains_length_cached > 0) {
    return kpf_nonce_domains_length_cached;
  }
  if(!kpf_nonce_domains_cached) {
    xpf_find_nonce_domains_array();
  }
  if(!kpf_nonce_domains_cached) {
    x8A4_log_error("Failed to get darwin_el2_init nonce_domains_array adrp!\n", "");
    return 0;
  }
  uint32_t mov_any_insn = 0;
  uint32_t mov_any_mask= 0;
  arm64_gen_mov_imm('z', ARM64_REG_ANY, OPT_UINT64_NONE, OPT_UINT64_NONE, &mov_any_insn, &mov_any_mask);
  uint64_t mov_addr = pfsec_find_next_inst(kernel_security_appleimage4_text_section, kpf_nonce_domains_cached,0x10, mov_any_insn, mov_any_mask);
  if(!mov_addr) {
    x8A4_log_error("Failed to get darwin_el2_init mov addr!\n", "");
    return 0;
  }
  uint64_t imm = 0;
  arm64_dec_mov_imm(pfsec_read32(kernel_security_appleimage4_text_section, mov_addr), NULL, &imm, NULL, NULL);
  kpf_nonce_domains_length_cached = (int)imm;
  return (int)imm;
}

/**
 * @brief           XPF Kernel patchfind the nonce domains array length
 * @param[in]       nonce_domains_array_addr
 * @return          Length of the nonce domains array
 */
int xpf_find_nonce_domains_array_length(uint64_t nonce_domains_array_addr) {
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
    return xpf_find_nonce_slots_array_length();
  }
  if(kpf_nonce_domains_length_cached > 0) {
    return kpf_nonce_domains_length_cached;
  }
  PFSection *kernel_security_appleimage4_text_section = NULL;
  PFSection *kernel_security_appleimage4_dataconst_section = NULL;
  PFSection *kernel_security_appleimage4_string_section = NULL;
  if (gXPF.kernelIsFileset) {
    if (xpf_setup_fileset_sections()) {
      return 0;
    }
    kernel_security_appleimage4_text_section = apple_image4_fileset_sections[0];
    kernel_security_appleimage4_dataconst_section = apple_image4_fileset_sections[1];
    kernel_security_appleimage4_string_section = apple_image4_fileset_sections[2];
  } else {
    if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
      kernel_security_appleimage4_text_section = gXPF.kernelPLKTextSection;
      kernel_security_appleimage4_dataconst_section = gXPF.kernelPLKTextSection;
      kernel_security_appleimage4_string_section =
          gXPF.kernelPrelinkTextSection;
    } else {
      kernel_security_appleimage4_text_section = gXPF.kernelTextSection;
      kernel_security_appleimage4_dataconst_section = gXPF.kernelTextSection;
      kernel_security_appleimage4_string_section = gXPF.kernelStringSection;
    }
  }
  if (!kernel_security_appleimage4_text_section ||
      !kernel_security_appleimage4_dataconst_section ||
      !kernel_security_appleimage4_string_section) {
    x8A4_log_error("Failed to setup kernel sections!\n", "");
    return 0;
  }
  PFXrefMetric *nonce_domains_array_xref_metric =
      pfmetric_xref_init(nonce_domains_array_addr, XREF_TYPE_MASK_REFERENCE);
  __block uint64_t nonce_domains_array_ref = 0;
  uint32_t b_cond_any_inst = 0, b_cond_any_mask = 0;
  arm64_gen_b_c_cond(OPT_BOOL(false), OPT_UINT64_NONE, OPT_UINT64_NONE,
                     ARM64_COND_ANY, &b_cond_any_inst, &b_cond_any_mask);
  pfmetric_run(kernel_security_appleimage4_text_section,
               nonce_domains_array_xref_metric, ^(uint64_t vmaddr, bool *stop) {
                 if (!pfsec_find_next_inst(
                         kernel_security_appleimage4_text_section, vmaddr - 12,
                         4, b_cond_any_inst, b_cond_any_mask)) {
                   nonce_domains_array_ref = vmaddr;
                   *stop = true;
                 }
               });
  pfmetric_free(nonce_domains_array_xref_metric);
  if (!nonce_domains_array_ref) {
    x8A4_log_error("Failed to find nonce domains array reference!\n", "");
    return 0;
  }
  uint32_t subs_any_inst = 0, subs_any_mask = 0;
  arm64_gen_sub_imm(ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE,
                    OPT_BOOL(true), &subs_any_inst, &subs_any_mask);
  uint64_t cmp = pfsec_find_prev_inst(kernel_security_appleimage4_text_section,
                                      nonce_domains_array_ref, 7, subs_any_inst,
                                      subs_any_mask);
  if (!cmp) {
    x8A4_log_error("Failed to find nonce domains array reference!\n", "");
    return 0;
  }
  uint16_t imm = 0;
  bool s = false;
  int ret = arm64_dec_sub_imm(
      pfsec_read32(kernel_security_appleimage4_text_section, cmp), NULL, NULL,
      &imm, &s);
  if (ret < 0 || !s) {
    x8A4_log_error("Failed to decode CMP instruction!\n", "");
    return 0;
  }
  kpf_nonce_domains_length_cached = (int)imm;
  return (int)imm;
}

#if 0
//    PFSection *list[] = {
//            gXPF.kernelTextSection,
//            gXPF.kernelPPLTextSection,
//            gXPF.kernelStringSection,
//            gXPF.kernelConstSection,
//            gXPF.kernelDataConstSection,
//            gXPF.kernelDataSection,
//            gXPF.kernelOSLogSection,
//            gXPF.kernelBootdataInit,
//            gXPF.kernelPrelinkTextSection,
//            gXPF.kernelPLKTextSection,
//            gXPF.kernelPLKDataConstSection,
//    };
//    for (int j = 0; j < 11; j++) {
//    }
#endif

/**
 * @brief           Iterate each nonce domains array entry until cryptex boot is found
 * @param[in]       nonce_domains_array_addr
 * @param[in]       nonce_domains_array_length
 * @return          Index of cryptex boot entry
 */
int xpf_find_cryptex_boot_domain_index(uint64_t nonce_domains_array_addr,
                                      int nonce_domains_array_length) {
  if (!nonce_domains_array_addr) {
    x8A4_log_error("Failure: nonce_domains_array_addr is zero!\n", "");
    return 0;
  }
  if (!nonce_domains_array_length) {
    x8A4_log_error("Failure: nonce_domains_array_length is zero!\n", "");
    return 0;
  }
  PFSection *kernel_security_appleimage4_text_section = NULL;
  PFSection *kernel_security_appleimage4_dataconst_section = NULL;
  PFSection *kernel_security_appleimage4_string_section = NULL;
  if (gXPF.kernelIsFileset) {
    if (xpf_setup_fileset_sections()) {
      return 0;
    }
    kernel_security_appleimage4_text_section = apple_image4_fileset_sections[0];
    kernel_security_appleimage4_dataconst_section = apple_image4_fileset_sections[1];
    kernel_security_appleimage4_string_section = apple_image4_fileset_sections[2];
  } else {
    if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
      kernel_security_appleimage4_text_section = gXPF.kernelPLKTextSection;
      kernel_security_appleimage4_dataconst_section =
          gXPF.kernelPLKDataConstSection;
      kernel_security_appleimage4_string_section =
          gXPF.kernelPrelinkTextSection;
    } else {
      kernel_security_appleimage4_text_section = gXPF.kernelTextSection;
      kernel_security_appleimage4_dataconst_section =
          gXPF.kernelDataConstSection;
      kernel_security_appleimage4_string_section = gXPF.kernelStringSection;
    }
  }
  if (!kernel_security_appleimage4_text_section ||
      !kernel_security_appleimage4_dataconst_section ||
      !kernel_security_appleimage4_string_section) {
    x8A4_log_error("Failed to setup kernel sections!\n", "");
    return 0;
  }
  int cryptex_index = -1;
  for (int i = 0; i < nonce_domains_array_length; i++) {
    uint64_t vmaddr = nonce_domains_array_addr + (i * sizeof(uint64_t));
    uint64_t ptr =
        pfsec_read64(kernel_security_appleimage4_dataconst_section, vmaddr);
    if (!ptr) {
      x8A4_log_error("i: %d: Failed read domain pointer from 0x%016llX!\n", i, vmaddr);
      continue;
    }
    if ((ptr & 0x8000000000000) != 0x8000000000000) {
      ptr &= 0x0000000fffffff;
      ptr += gXPF.kernelBase - 0x7004000;
    }
    vmaddr = ptr;
    ptr = pfsec_read64(kernel_security_appleimage4_dataconst_section,
                       vmaddr + sizeof(uint64_t));
    if (!ptr) {
      x8A4_log_error("i: %d: Failed read domain pointer 2 from 0x%016llX!\n", i, vmaddr);
      continue;
    }
    if ((ptr & 0x8000000000000) != 0x8000000000000) {
      ptr &= 0x0000000fffffff;
      ptr += gXPF.kernelBase - 0x7004000;
    }
    char *domain = NULL;
    int ret = pfsec_read_string(kernel_security_appleimage4_string_section, ptr,
                                &domain);
    if (ret != 0 || !domain) {
      x8A4_log_error("Failed read domain string from 0x%llX ret: %d pointer: 0x%016llX!\n", nonce_domains_array_addr + (i * sizeof(uint64_t)), ret, (uint64_t)domain);
      continue;
    }
    if (strcmp("com.apple.private.img4.nonce.cryptex1.boot", domain) == 0) {
      cryptex_index = i;
      break;
    }
  }
  if (cryptex_index < 0) {
    x8A4_log_error("Failed find cryptex domain index!\n", "");
  }
  return cryptex_index;
}
