/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/ieee1275/ieee1275.h>
#include <grub/types.h>
#include <grub/misc.h>

/* Sun specific ieee1275 interfaces used by GRUB.  */

int
grub_ieee1275_claim_vaddr (grub_addr_t vaddr, grub_size_t size)
{
  struct claim_vaddr_args
  {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t method;
    grub_ieee1275_cell_t ihandle;
    grub_ieee1275_cell_t align;
    grub_ieee1275_cell_t size;
    grub_ieee1275_cell_t virt;
    grub_ieee1275_cell_t catch_result;
  }
  args;

  INIT_IEEE1275_COMMON (&args.common, "call-method", 5, 2);
  args.method = (grub_ieee1275_cell_t) "claim";
  args.ihandle = grub_ieee1275_mmu;
  args.align = 0;
  args.size = size;
  args.virt = vaddr;
  args.catch_result = (grub_ieee1275_cell_t) -1;

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;
  return args.catch_result;
}

int
grub_ieee1275_alloc_physmem (grub_addr_t *paddr, grub_size_t size,
			     grub_uint32_t align)
{
  grub_uint32_t memory_ihandle;
  struct alloc_physmem_args
  {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t method;
    grub_ieee1275_cell_t ihandle;
    grub_ieee1275_cell_t align;
    grub_ieee1275_cell_t size;
    grub_ieee1275_cell_t catch_result;
    grub_ieee1275_cell_t phys_high;
    grub_ieee1275_cell_t phys_low;
  }
  args;
  grub_ssize_t actual = 0;

  grub_ieee1275_get_property (grub_ieee1275_chosen, "memory",
			      &memory_ihandle, sizeof (memory_ihandle),
			      &actual);
  if (actual != sizeof (memory_ihandle))
    return -1;

  if (!align)
    align = 1;

  INIT_IEEE1275_COMMON (&args.common, "call-method", 4, 3);
  args.method = (grub_ieee1275_cell_t) "claim";
  args.ihandle = memory_ihandle;
  args.align = (align ? align : 1);
  args.size = size;
  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  *paddr = args.phys_low;

  return args.catch_result;
}

int
grub_ieee1275_set_sas_address (grub_ieee1275_ihandle_t ihandle,
                               const char *disk_name,
                               grub_uint64_t lun)
{
  struct dev_set_address
  {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t method;
    grub_ieee1275_cell_t ihandle;
    grub_ieee1275_cell_t tgt_h;
    grub_ieee1275_cell_t tgt_l;
    grub_ieee1275_cell_t lun_h;
    grub_ieee1275_cell_t lun_l;
    grub_ieee1275_cell_t catch_result;
  }
  args;

  grub_uint32_t sas_phy = 0, tgt = 0;
  grub_uint64_t wwn = 0;

  if (disk_name == 0)
    return -1;

  INIT_IEEE1275_COMMON (&args.common, "call-method", 6, 1);
  args.method = (grub_ieee1275_cell_t) "set-address";
  args.ihandle = ihandle;
  args.lun_l = lun & 0xffffffff;
  args.lun_h = lun >> 32;

  /* PHY addressing */
  if (*disk_name == 'p')
    {
      /*         Bit #   33222222 22221111 11111100 00000000
                         10987654 32109876 54321098 76543210

         sas.hi cell:    00000000 00000000 00000000 00000000
         sas.lo cell:    00000000 00000001 jjjjjjjj iiiiiiii
         lun.hi cell:    uuuuuuuu uuuuuuuu uuuuuuuu uuuuuuuu
         lun.lo cell:    uuuuuuuu uuuuuuuu uuuuuuuu uuuuuuuu

         00..00          Bits with the value zero
         ii..ii          8-bit unsigned number phy identifier in the range
                         of 0..FE .
         jj..jj          Expander identifier. Either zero (indicating the PHY number
                         iiiiiiii is on the SAS adapter itself) or identifies the PHY
                         connecting to the expander, in which case iiiiiiii identifies
                         a PHY on a SAS expander. In the non-zero case, jjjjjjjj is an
                         8-bit unsigned number of the PHY plus one, in the range 1..FF
         uu..uu          64-bit unsigned number logical unit number
      */
      sas_phy = grub_strtoul (disk_name + 1, 0, 16);
      args.tgt_l = 0x10000 | sas_phy;
      args.tgt_h = 0;
    }
  /* WWN addressing */
  else if ((*disk_name =='w') && (*(disk_name + 1) == '5'))
    {
      /*          Bit #   33222222 22221111 11111100 00000000
                          10987654 32109876 54321098 76543210

          sas.hi cell:    0101vvvv vvvvvvvv vvvvvvvv vvvvssss
          sas.lo cell:    ssssssss ssssssss ssssssss ssssssss
          lun.hi cell:    uuuuuuuu uuuuuuuu uuuuuuuu uuuuuuuu
          lun.lo cell:    uuuuuuuu uuuuuuuu uuuuuuuu uuuuuuuu

          0101            The value "5" in the high-order NAA nibble
          vv..vv          24-bit IEEE Organization ID
          ss..ss          36-bit unsigned device serial number
          uu..uu          64-bit unsigned number logical unit number
      */
      wwn = grub_strtoull (disk_name + 1, 0, 16);
      args.tgt_l = wwn & 0xffffffff;
      args.tgt_h = wwn >> 32;
    }
   /* Target LUN addressing */
   else if (grub_isxdigit (*disk_name))
    {
      /* Deprecated
                  Bit #   33222222 22221111 11111100 00000000
                          10987654 32109876 54321098 76543210

          sas.hi cell:    00000000 00000000 00000000 00000000
          sas.lo cell:    00000000 00000000 00000000 tttttttt
          lun.hi cell:    uuuuuuuu uuuuuuuu uuuuuuuu uuuuuuuu
          lun.lo cell:    uuuuuuuu uuuuuuuu uuuuuuuu uuuuuuuu

          00..00          Bits with the value zero
          tt..tt          8-bit unsigned number target identifier in the range
                          of 0..FF
          uu..uu          64-bit unsigned number logical unit number
      */
      tgt = grub_strtol (disk_name, 0, 16);
      if (tgt <= 0xff)
        {
          args.tgt_l = tgt;
          args.tgt_h = 0;
        }
      else
        return -1;
    }
  else
    return -1;

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  return args.catch_result;
}
