/* ofdisk.c - Open Firmware disk access.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2004,2006,2007,2008,2009  Free Software Foundation, Inc.
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

#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/mm.h>
#include <grub/ieee1275/ieee1275.h>
#include <grub/ieee1275/ofdisk.h>
#include <grub/scsicmd.h>
#include <grub/i18n.h>
#include <grub/time.h>
#include <grub/list.h>

static char *last_devpath;
static grub_ieee1275_ihandle_t last_ihandle;

struct ofdisk_hash_ent
{
  char *devpath;
  char *open_path;
  char *grub_devpath;
  int is_boot;
  int is_removable;
  int block_size_retries;
  grub_uint32_t block_size;
  grub_ieee1275_ihandle_t ihandle;
  /* Pointer to shortest available name on nodes representing canonical names,
     otherwise NULL.  */
  const char *shortest;
  const char *grub_shortest;
  struct ofdisk_hash_ent *next;
};

struct ofdisk_hba_ent
{
  struct ofdisk_hba_ent *next;
  struct ofdisk_hba_ent **prev;
  grub_ieee1275_ihandle_t ihandle;
  char *path;
};

static grub_err_t
grub_ofdisk_get_block_size (grub_uint32_t *block_size,
                            struct ofdisk_hash_ent *op);

static grub_err_t
grub_ofdisk_open_real (grub_disk_t disk);

#define OFDISK_HASH_SZ	8
static struct ofdisk_hash_ent *ofdisk_hash[OFDISK_HASH_SZ];

#ifdef __sparc__
static grub_err_t
sparc_disk_present (const char *path);

static char *
get_hbaname_from_path (const char *path);

static char *
get_diskname_from_path (const char *path);

static struct ofdisk_hba_ent *
ofdisk_hba_find (const char *devpath);

static grub_ieee1275_ihandle_t
ofdisk_hba_open (const char *hba_name);

static struct ofdisk_hba_ent *ofdisk_hba_ents = NULL;

static struct grub_scsi_test_unit_ready ofdisk_tur =
{
  .opcode = grub_scsi_cmd_test_unit_ready,
  .lun = 0,
  .reserved1 = 0,
  .reserved2 = 0,
  .reserved3 = 0,
  .control = 0,
};
#endif

static int
ofdisk_hash_fn (const char *devpath)
{
  int hash = 0;
  while (*devpath)
    hash ^= *devpath++;
  return (hash & (OFDISK_HASH_SZ - 1));
}

static struct ofdisk_hash_ent *
ofdisk_hash_find (const char *devpath)
{
  struct ofdisk_hash_ent *p = ofdisk_hash[ofdisk_hash_fn(devpath)];

  while (p)
    {
      if (!grub_strcmp (p->devpath, devpath))
	break;
      p = p->next;
    }
  return p;
}

static struct ofdisk_hash_ent *
ofdisk_hash_add_real (const char *devpath)
{
  struct ofdisk_hash_ent *p;
  struct ofdisk_hash_ent **head = &ofdisk_hash[ofdisk_hash_fn(devpath)];
  const char *iptr;
  char *optr;

  p = grub_zalloc (sizeof (*p));
  if (!p)
    return NULL;

  p->devpath = grub_strdup (devpath);

  if (!p->devpath)
    {
      grub_free (p);
      return NULL;
    }

  p->grub_devpath = grub_malloc (sizeof ("ieee1275/")
				 + 2 * grub_strlen (p->devpath));

  if (!p->grub_devpath)
    {
      grub_free (p->devpath);
      grub_free (p);
      return NULL;
    }

  if (! grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_NO_PARTITION_0))
    {
      p->open_path = grub_malloc (grub_strlen (p->devpath) + 3);
      if (!p->open_path)
	{
          grub_free (p->devpath);
	  grub_free (p->grub_devpath);
	  grub_free (p);
	  return NULL;
	}
      optr = grub_stpcpy (p->open_path, p->devpath);
      *optr++ = ':';
      *optr++ = '0';
      *optr = '\0';
    }
  else
    p->open_path = p->devpath;

  optr = grub_stpcpy (p->grub_devpath, "ieee1275/");
  for (iptr = p->devpath; *iptr; )
    {
      if (*iptr == ',')
	*optr++ = '\\';
      *optr++ = *iptr++;
    }
  *optr = 0;

  p->next = *head;
  *head = p;
  return p;
}

static int
check_string_removable (const char *str)
{
  const char *ptr = grub_strrchr (str, '/');

  if (ptr)
    ptr++;
  else
    ptr = str;
  return (grub_strncmp (ptr, "cdrom", 5) == 0 || grub_strncmp (ptr, "fd", 2) == 0);
}

static struct ofdisk_hash_ent *
ofdisk_hash_add (const char *devpath, const char *curcan)
{
  struct ofdisk_hash_ent *p, *pcan;

  p = ofdisk_hash_add_real (devpath);

  grub_dprintf ("disk", "devpath = %s, canonical = %s\n", devpath, curcan);

  if (!curcan)
    {
      p->shortest = p->devpath;
      p->grub_shortest = p->grub_devpath;
      if (check_string_removable (devpath))
	p->is_removable = 1;
      return p;
    }

  pcan = ofdisk_hash_find (curcan);
  if (!pcan)
    pcan = ofdisk_hash_add_real (curcan);

  if (check_string_removable (devpath) || check_string_removable (curcan))
    pcan->is_removable = 1;

  if (!pcan)
    grub_errno = GRUB_ERR_NONE;
  else
    {
      if (!pcan->shortest
	  || grub_strlen (pcan->shortest) > grub_strlen (devpath))
	{
	  pcan->shortest = p->devpath;
	  pcan->grub_shortest = p->grub_devpath;
	}
    }

  return p;
}

static void
dev_iterate_real (const char *name, const char *path)
{
  struct ofdisk_hash_ent *op;

  grub_dprintf ("disk", "disk name = %s, path = %s\n", name,
		path);

  op = ofdisk_hash_find (path);
  if (!op)
    op = ofdisk_hash_add (name, path);
  return;
}

static void
dev_iterate (const struct grub_ieee1275_devalias *alias)
{
  if (grub_strcmp (alias->type, "vscsi") == 0)
    {
      static grub_ieee1275_ihandle_t ihandle;
      struct set_color_args
      {
	struct grub_ieee1275_common_hdr common;
	grub_ieee1275_cell_t method;
	grub_ieee1275_cell_t ihandle;
	grub_ieee1275_cell_t catch_result;
	grub_ieee1275_cell_t nentries;
	grub_ieee1275_cell_t table;
      }
      args;
      char *buf, *bufptr;
      unsigned i;

      if (grub_ieee1275_open (alias->path, &ihandle))
	return;

      /* This method doesn't need memory allocation for the table. Open
         firmware takes care of all memory management and the result table
         stays in memory and is never freed. */
      INIT_IEEE1275_COMMON (&args.common, "call-method", 2, 3);
      args.method = (grub_ieee1275_cell_t) "vscsi-report-luns";
      args.ihandle = ihandle;
      args.table = 0;
      args.nentries = 0;

      if (IEEE1275_CALL_ENTRY_FN (&args) == -1 || args.catch_result)
	{
	  grub_ieee1275_close (ihandle);
	  return;
	}

      buf = grub_malloc (grub_strlen (alias->path) + 32);
      if (!buf)
	return;
      bufptr = grub_stpcpy (buf, alias->path);

      for (i = 0; i < args.nentries; i++)
	{
	  grub_uint64_t *ptr;

	  ptr = *(grub_uint64_t **) (args.table + 4 + 8 * i);
	  while (*ptr)
	    {
	      grub_snprintf (bufptr, 32, "/disk@%" PRIxGRUB_UINT64_T, *ptr++);
	      dev_iterate_real (buf, buf);
	    }
	}
      grub_ieee1275_close (ihandle);
      grub_free (buf);
      return;
    }
  else if (grub_strcmp (alias->type, "sas_ioa") == 0)
    {
      /* The method returns the number of disks and a table where
       * each ID is 64-bit long. Example of sas paths:
       *  /pci@80000002000001f/pci1014,034A@0/sas/disk@c05db70800
       *  /pci@80000002000001f/pci1014,034A@0/sas/disk@a05db70800
       *  /pci@80000002000001f/pci1014,034A@0/sas/disk@805db70800 */

      struct sas_children
        {
          struct grub_ieee1275_common_hdr common;
          grub_ieee1275_cell_t method;
          grub_ieee1275_cell_t ihandle;
          grub_ieee1275_cell_t max;
          grub_ieee1275_cell_t table;
          grub_ieee1275_cell_t catch_result;
          grub_ieee1275_cell_t nentries;
        }
      args;
      char *buf, *bufptr;
      unsigned i;
      grub_uint64_t *table;
      grub_uint16_t table_size;
      grub_ieee1275_ihandle_t ihandle;

      buf = grub_malloc (grub_strlen (alias->path) +
                         sizeof ("/disk@7766554433221100"));
      if (!buf)
        return;
      bufptr = grub_stpcpy (buf, alias->path);

      /* Power machines documentation specify 672 as maximum SAS disks in
         one system. Using a slightly larger value to be safe. */
      table_size = 768;
      table = grub_malloc (table_size * sizeof (grub_uint64_t));

      if (!table)
        {
          grub_free (buf);
          return;
        }

      if (grub_ieee1275_open (alias->path, &ihandle))
        {
          grub_free (buf);
          grub_free (table);
          return;
        }

      INIT_IEEE1275_COMMON (&args.common, "call-method", 4, 2);
      args.method = (grub_ieee1275_cell_t) "get-sas-children";
      args.ihandle = ihandle;
      args.max = table_size;
      args.table = (grub_ieee1275_cell_t) table;
      args.catch_result = 0;
      args.nentries = 0;

      if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
        {
          grub_ieee1275_close (ihandle);
          grub_free (table);
          grub_free (buf);
          return;
        }

      for (i = 0; i < args.nentries; i++)
        {
          grub_snprintf (bufptr, sizeof ("/disk@7766554433221100"),
                        "/disk@%" PRIxGRUB_UINT64_T, table[i]);
          dev_iterate_real (buf, buf);
        }

      grub_ieee1275_close (ihandle);
      grub_free (table);
      grub_free (buf);
    }
#ifdef __sparc__
  else if (grub_strcmp (alias->type, "scsi-2") == 0)
    {
      grub_ieee1275_ihandle_t ihandle;
      grub_ssize_t result;
      char *buf, *bufptr;
      grub_uint8_t tgt;

      buf = grub_malloc (grub_strlen (alias->path) +
                         sizeof ("/disk@00"));
      if (!buf)
        return;

      bufptr = grub_stpcpy (buf, alias->path);
      ihandle = ofdisk_hba_open (alias->path);

      if (ihandle == 0)
        {
          grub_free (buf);
          return;
        }

      for (tgt = 0; tgt <= 0xf; tgt++)
        {
          if (grub_ieee1275_set_address(ihandle, tgt, 0) == 0)
            if (grub_ieee1275_no_data_command (ihandle, &ofdisk_tur,
                                               &result) == 0)
              if (result == 0)
                {
                  grub_snprintf (bufptr, sizeof ("/disk@00"),
                                 "/disk@%" PRIxGRUB_UINT32_T, tgt);
                  dev_iterate_real (buf, buf);
                }
        }

      grub_free (buf);
      return;
    }
  else if (grub_strcmp (alias->type, "scsi-sas") == 0)
    {
      grub_ieee1275_ihandle_t ihandle;
      grub_uint32_t address_cells = 2;
      grub_ieee1275_phandle_t root;
      grub_ssize_t result;
      char *buf, *bufptr;

      buf = grub_malloc (grub_strlen (alias->path) +
                         sizeof ("/disk@p1100"));

      if (!buf)
        return;

      bufptr = grub_stpcpy (buf, alias->path);
      bufptr = grub_stpcpy (bufptr, "/disk@");
      ihandle = ofdisk_hba_open (alias->path);

      if (ihandle == 0)
        {
          grub_free (buf);
          return;
        }

      grub_ieee1275_finddevice (alias->path, &root);
      grub_ieee1275_get_integer_property (root, "#address-cells", &address_cells,
                                          sizeof address_cells, 0);
      if (address_cells == 2)
        {
          grub_uint8_t tgt;

          for (tgt = 0; tgt < 0xf; tgt++)
            {
              if (grub_ieee1275_set_address(ihandle, tgt, 0) == 0)
                if (grub_ieee1275_no_data_command (ihandle, &ofdisk_tur,
                                                   &result) == 0)
                  if (result == 0)
                    {
                      grub_snprintf (bufptr, sizeof ("p1100"),
                                     "%" PRIxGRUB_UINT32_T, tgt);
                      dev_iterate_real (buf, buf);
                    }
            }
        }
      else if (address_cells == 4)
        {
          grub_uint16_t exp;
          grub_uint8_t phy;

          for (exp = 0; exp <= 0x100; exp+=0x100)
            for (phy = 0; phy < 0xff; phy++)
              {
                grub_snprintf (bufptr, sizeof ("p1100"),
                               "p%" PRIxGRUB_UINT32_T, exp | phy);
                if (grub_ieee1275_set_sas_address (ihandle, bufptr, 0) == 0)
                  if (grub_ieee1275_no_data_command (ihandle, &ofdisk_tur,
                                                     &result) == 0)
                    if (result == 0)
                      dev_iterate_real (buf, buf);
              }
        }
      grub_free (buf);
      return;
    }
  else if (grub_strcmp (alias->type, "nvme") == 0)
    {
      char *buf;

      buf = grub_malloc (IEEE1275_MAX_PATH_LEN);

      if (!buf)
        return;

      grub_snprintf (buf, IEEE1275_MAX_PATH_LEN, "%s/disk@1", alias->path);
      dev_iterate_real (buf, buf);
      grub_free (buf);
      return;
    }
  else if (grub_strcmp (alias->type, "scsi-usb") == 0)
    {
      grub_ieee1275_ihandle_t ihandle;
      grub_ssize_t result;

      ihandle = ofdisk_hba_open (alias->path);

      if (ihandle == 0)
        return;

      if (grub_ieee1275_set_address (ihandle, 0, 0) == 0)
        if (grub_ieee1275_no_data_command (ihandle, &ofdisk_tur, &result) == 0)
          if (result == 0)
            {
              char *buf, *bufptr;

              buf = grub_malloc (grub_strlen (alias->path) +
                                 sizeof ("/disk@0"));

              if (!buf)
                return;

              bufptr = grub_stpcpy (buf, alias->path);
              grub_snprintf (bufptr, sizeof ("/disk@0"), "/disk@0");
              dev_iterate_real (buf, buf);
              grub_free (buf);
            }
      return;
    }
#endif

  if (!grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_NO_TREE_SCANNING_FOR_DISKS)
      && grub_strcmp (alias->type, "block") == 0)
    {
      if (grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_IGNORE_REBOOT_DEV)
          && grub_strstr (alias->path, "reboot-memory"))
        return;
      dev_iterate_real (alias->path, alias->path);
      return;
    }

  {
    struct grub_ieee1275_devalias child;

    FOR_IEEE1275_DEVCHILDREN(alias->path, child)
      dev_iterate (&child);
  }
}

static void
scan (void)
{
  struct grub_ieee1275_devalias alias;
  FOR_IEEE1275_DEVALIASES(alias)
    {
      if (grub_strcmp (alias.type, "block") != 0)
	continue;
#ifdef __sparc__
      if (grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_VALIDATE_DEV_ALIASES) &&
          sparc_disk_present (alias.path) == 0)
        continue;
#endif
      dev_iterate_real (alias.name, alias.path);
    }

  FOR_IEEE1275_DEVCHILDREN("/", alias)
    dev_iterate (&alias);
}

static int
grub_ofdisk_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data,
		     grub_disk_pull_t pull)
{
  unsigned i;

  if (pull != GRUB_DISK_PULL_NONE)
    return 0;

  scan ();
  
  for (i = 0; i < ARRAY_SIZE (ofdisk_hash); i++)
    {
      static struct ofdisk_hash_ent *ent;
      for (ent = ofdisk_hash[i]; ent; ent = ent->next)
	{
	  if (!ent->shortest)
	    continue;
	  if (grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_OFDISK_SDCARD_ONLY))
	    {
	      grub_ieee1275_phandle_t dev;
	      char tmp[8];

	      if (grub_ieee1275_finddevice (ent->devpath, &dev))
		{
		  grub_dprintf ("disk", "finddevice (%s) failed\n",
				ent->devpath);
		  continue;
		}

	      if (grub_ieee1275_get_property (dev, "iconname", tmp,
					      sizeof tmp, 0))
		{
		  grub_dprintf ("disk", "get iconname failed\n");
		  continue;
		}

	      if (grub_strcmp (tmp, "sdmmc") != 0)
		{
		  grub_dprintf ("disk", "device is not an SD card\n");
		  continue;
		}
	    }

	  if (!ent->is_boot && ent->is_removable)
	    continue;

	  if (hook (ent->grub_shortest, hook_data))
	    return 1;
	}
    }	  
  return 0;
}

static char *
compute_dev_path (const char *name)
{
  char *devpath = grub_malloc (grub_strlen (name) + 3);
  char *p, c;

  if (!devpath)
    return NULL;

  /* Un-escape commas. */
  p = devpath;
  while ((c = *name++) != '\0')
    {
      if (c == '\\' && *name == ',')
	{
	  *p++ = ',';
	  name++;
	}
      else
	*p++ = c;
    }

  *p++ = '\0';

  return devpath;
}

#ifdef __sparc__
static char *
get_hbaname_from_path (const char *path)
{
  char *sptr, *hba_name;

  hba_name = grub_strdup (path);

  if (!hba_name)
    return NULL;

  sptr = grub_strstr (hba_name, "/disk@");

  if (!sptr)
    return NULL;

  *sptr = '\0';

  return hba_name;
}

static char *
get_diskname_from_path (const char *path)
{
  const char *disk_dev = "/disk@";
  char *sptr, *disk_name;

  sptr = grub_strstr (path, disk_dev);

  if (!sptr)
    return NULL;

  disk_name = grub_strdup (sptr + grub_strlen (disk_dev));
  sptr = grub_strstr (disk_name, ":");

  if (sptr)
    *sptr = '\0';

  return disk_name;
}
#endif

static grub_err_t
grub_ofdisk_open (const char *name, grub_disk_t disk)
{
  grub_ieee1275_phandle_t dev;
  char *devpath;
  /* XXX: This should be large enough for any possible case.  */
  char prop[64];
  grub_ssize_t actual;
  grub_uint32_t block_size = 0;
  grub_err_t err;

  if (grub_strncmp (name, "ieee1275/", sizeof ("ieee1275/") - 1) != 0)
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE,
			 "not IEEE1275 device");
  devpath = compute_dev_path (name + sizeof ("ieee1275/") - 1);
  if (! devpath)
    return grub_errno;

  grub_dprintf ("disk", "Opening `%s'.\n", devpath);

  if (grub_ieee1275_finddevice (devpath, &dev))
    {
      grub_free (devpath);
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE,
			 "can't read device properties");
    }

  if (grub_ieee1275_get_property (dev, "device_type", prop, sizeof (prop),
				  &actual))
    {
      grub_free (devpath);
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "can't read the device type");
    }

  if (grub_strcmp (prop, "block"))
    {
      grub_free (devpath);
      return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "not a block device");
    }

  /* XXX: There is no property to read the number of blocks.  There
     should be a property `#blocks', but it is not there.  Perhaps it
     is possible to use seek for this.  */
  disk->total_sectors = GRUB_DISK_SIZE_UNKNOWN;

  {
    struct ofdisk_hash_ent *op;
    op = ofdisk_hash_find (devpath);
    if (!op)
      op = ofdisk_hash_add (devpath, NULL);
    if (!op)
      {
        grub_free (devpath);
        return grub_errno;
      }
    disk->id = (unsigned long) op;
    disk->data = op->open_path;
    err = grub_ofdisk_open_real (disk);
    if (err)
      {
        grub_free (devpath);
        return err;
      }

    err = grub_ofdisk_get_block_size (&block_size, op);
    if (err)
      {
        grub_free (devpath);
        return err;
      }
    if (block_size != 0)
      {
	for (disk->log_sector_size = 0;
	     (1U << disk->log_sector_size) < block_size;
	     disk->log_sector_size++);
      }
    else
      disk->log_sector_size = 9;
  }

  grub_free (devpath);
  return 0;
}

static void
grub_ofdisk_close (grub_disk_t disk)
{
  if (disk->data == last_devpath)
    {
      if (! (grub_ieee1275_test_flag(GRUB_IEEE1275_FLAG_CACHE_OPEN)) && last_ihandle)
	grub_ieee1275_close (last_ihandle);
      last_ihandle = 0;
      last_devpath = NULL;
    }
  disk->data = 0;
}

static grub_err_t
grub_ofdisk_prepare (grub_disk_t disk, grub_disk_addr_t sector)
{
  grub_ssize_t status;
  unsigned long long pos;
  grub_err_t err;

  if (disk->data != last_devpath)
    {
      err = grub_ofdisk_open_real (disk);
      if (err)
        return err;
      last_devpath = disk->data;      
    }

  pos = sector << disk->log_sector_size;

  grub_ieee1275_seek (last_ihandle, pos, &status);
  if (status < 0)
    return grub_error (GRUB_ERR_READ_ERROR,
		       "seek error, can't seek block %llu",
		       (long long) sector);
  return 0;
}

static grub_err_t
grub_ofdisk_read (grub_disk_t disk, grub_disk_addr_t sector,
		  grub_size_t size, char *buf)
{
  grub_err_t err;
  grub_ssize_t actual;
  err = grub_ofdisk_prepare (disk, sector);
  if (err)
    return err;
  grub_ieee1275_read (last_ihandle, buf, size  << disk->log_sector_size,
		      &actual);
  if (actual != (grub_ssize_t) (size  << disk->log_sector_size))
    return grub_error (GRUB_ERR_READ_ERROR, N_("failure reading sector 0x%llx "
					       "from `%s'"),
		       (unsigned long long) sector,
		       disk->name);

  return 0;
}

static grub_err_t
grub_ofdisk_write (grub_disk_t disk, grub_disk_addr_t sector,
		   grub_size_t size, const char *buf)
{
  grub_err_t err;
  grub_ssize_t actual;
  err = grub_ofdisk_prepare (disk, sector);
  if (err)
    return err;
  grub_ieee1275_write (last_ihandle, buf, size  << disk->log_sector_size,
		       &actual);
  if (actual != (grub_ssize_t) (size << disk->log_sector_size))
    return grub_error (GRUB_ERR_WRITE_ERROR, N_("failure writing sector 0x%llx "
						"to `%s'"),
		       (unsigned long long) sector,
		       disk->name);

  return 0;
}

static struct grub_disk_dev grub_ofdisk_dev =
  {
    .name = "ofdisk",
    .id = GRUB_DISK_DEVICE_OFDISK_ID,
    .iterate = grub_ofdisk_iterate,
    .open = grub_ofdisk_open,
    .close = grub_ofdisk_close,
    .read = grub_ofdisk_read,
    .write = grub_ofdisk_write,
    .next = 0
  };

static void
insert_bootpath (void)
{
  char *bootpath;
  grub_ssize_t bootpath_size;
  char *type;

  if (grub_ieee1275_get_property_length (grub_ieee1275_chosen, "bootpath",
					 &bootpath_size)
      || bootpath_size <= 0)
    {
      /* Should never happen.  */
      grub_printf ("/chosen/bootpath property missing!\n");
      return;
    }

  bootpath = (char *) grub_malloc ((grub_size_t) bootpath_size + 64);
  if (! bootpath)
    {
      grub_print_error ();
      return;
    }
  grub_ieee1275_get_property (grub_ieee1275_chosen, "bootpath", bootpath,
                              (grub_size_t) bootpath_size + 1, 0);
  bootpath[bootpath_size] = '\0';

  /* Transform an OF device path to a GRUB path.  */

  type = grub_ieee1275_get_device_type (bootpath);
  if (!(type && grub_strcmp (type, "network") == 0))
    {
      struct ofdisk_hash_ent *op;
      char *device = grub_ieee1275_get_devname (bootpath);
      op = ofdisk_hash_add (device, NULL);
      op->is_boot = 1;
      grub_free (device);
    }
  grub_free (type);
  grub_free (bootpath);
}

void
grub_ofdisk_fini (void)
{
  if (grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_CACHE_OPEN))
    {
      struct ofdisk_hba_ent *dev = NULL;
      struct ofdisk_hash_ent *ent;
      int i;

      for (i = 0; i < ARRAY_SIZE (ofdisk_hash); i++)
        {
          struct ofdisk_hash_ent *ent;

          for (ent = ofdisk_hash[i]; ent; ent = ent->next)
            if (ent->ihandle)
              grub_ieee1275_close (ent->ihandle);
        }

      FOR_LIST_ELEMENTS (dev, ofdisk_hba_ents)
        grub_ieee1275_close (dev->ihandle);
    }
  else if (last_ihandle)
    grub_ieee1275_close (last_ihandle);

  last_ihandle = 0;
  last_devpath = NULL;

  grub_disk_dev_unregister (&grub_ofdisk_dev);
}

void
grub_ofdisk_init (void)
{
  grub_disk_firmware_fini = grub_ofdisk_fini;

  insert_bootpath ();

  grub_disk_dev_register (&grub_ofdisk_dev);
}

static grub_err_t
grub_ofdisk_get_block_size (grub_uint32_t *block_size, struct ofdisk_hash_ent *op)
{
  struct size_args_ieee1275
    {
      struct grub_ieee1275_common_hdr common;
      grub_ieee1275_cell_t method;
      grub_ieee1275_cell_t ihandle;
      grub_ieee1275_cell_t result;
      grub_ieee1275_cell_t size1;
      grub_ieee1275_cell_t size2;
    } args_ieee1275;

  if ((op->block_size_retries >= 2) || (op->block_size > 0))
    {
      *block_size = op->block_size;
      return GRUB_ERR_NONE;
    }

  *block_size = 0;

  op->block_size_retries++;

  INIT_IEEE1275_COMMON (&args_ieee1275.common, "call-method", 2, 2);
  args_ieee1275.method = (grub_ieee1275_cell_t) "block-size";
  args_ieee1275.ihandle = last_ihandle;
  args_ieee1275.result = 1;

  if (IEEE1275_CALL_ENTRY_FN (&args_ieee1275) == -1)
    grub_dprintf ("disk", "can't get block size: failed call-method\n");
  else if (args_ieee1275.result)
    grub_dprintf ("disk", "can't get block size: %lld\n",
		 (long long) args_ieee1275.result);
  else if (args_ieee1275.size1
	   && !(args_ieee1275.size1 & (args_ieee1275.size1 - 1))
	   && args_ieee1275.size1 >= 512 && args_ieee1275.size1 <= 16384)
    {
      op->block_size = args_ieee1275.size1;
      *block_size = args_ieee1275.size1;
    }

  return 0;
}

static grub_err_t
grub_ofdisk_open_real (grub_disk_t disk)
{
  struct ofdisk_hash_ent *op = (struct ofdisk_hash_ent *)disk->id;

  if (!op)
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "BUG: can't open device ");

  if (grub_ieee1275_test_flag(GRUB_IEEE1275_FLAG_CACHE_OPEN) && op->ihandle)
    {
      last_ihandle = op->ihandle;
      last_devpath = disk->data;
      return 0;
    }

  if (last_ihandle)
    grub_ieee1275_close (last_ihandle);

  last_ihandle = 0;
  last_devpath = NULL;

  grub_ieee1275_open (disk->data, &last_ihandle);
  if (! last_ihandle)
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "can't open device");

  op->ihandle = last_ihandle;
  last_devpath = disk->data;
  return 0;
}

#ifdef __sparc__
static struct ofdisk_hba_ent *
ofdisk_hba_find (const char *devpath)
{
  struct ofdisk_hba_ent *dev = NULL;

  FOR_LIST_ELEMENTS (dev, ofdisk_hba_ents)
    if (grub_strcmp (dev->path, devpath) == 0)
      break;

  return dev;
}

static struct ofdisk_hba_ent *
ofdisk_hba_add (const char *devpath, grub_ieee1275_ihandle_t ihandle)
{
  struct ofdisk_hba_ent *dev;

  dev = grub_zalloc (sizeof (struct ofdisk_hba_ent));

  if (!dev)
    return NULL;

  dev->path = grub_strdup (devpath);

  if (!dev->path)
    {
      grub_free (dev);
      return NULL;
    }

  dev->ihandle = ihandle;
  grub_list_push (GRUB_AS_LIST_P (&ofdisk_hba_ents), GRUB_AS_LIST (dev));

  return dev;
}

static grub_ieee1275_ihandle_t
ofdisk_hba_open (const char *hba_name)
{
  grub_ieee1275_ihandle_t ihandle;
  struct ofdisk_hba_ent *dev;

  dev = ofdisk_hba_find (hba_name);

  if (dev)
    ihandle = dev->ihandle;
  else if (grub_ieee1275_open (hba_name, &ihandle))
    ihandle = 0;
  else
    {
      dev = ofdisk_hba_add (hba_name, ihandle);

      if (!dev)
        ihandle = 0;
    }

  return ihandle;
}

static grub_err_t
sparc_disk_present (const char *full_path)
{
  char *disk_name = get_diskname_from_path (full_path);
  char *hba_name = get_hbaname_from_path (full_path);
  char *lun_name = NULL, *sptr = NULL, *device_type = 0;
  grub_ieee1275_ihandle_t ihandle;
  /* Per SPARC SCSI binding spec, default to 2 for legacy devices that may
     not have this property */
  grub_uint32_t address_cells = 2;
  grub_ieee1275_phandle_t root;
  grub_uint64_t lun = 0;
  grub_ssize_t result;
  grub_err_t rval = GRUB_ERR_NONE;

  if ((!hba_name) || (!disk_name))
    {
      grub_free (hba_name);
      grub_free (disk_name);
      return GRUB_ERR_NONE;
    }

  ihandle = ofdisk_hba_open (hba_name);

  if (ihandle == 0)
    {
      grub_free (hba_name);
      grub_free (disk_name);
      return GRUB_ERR_NONE;
    }

  sptr = grub_strstr (disk_name, ",");

  if (sptr)
    {
      lun_name = grub_strdup (sptr + 1);
      *sptr = '\0';
      lun = grub_strtoull (lun_name, 0, 16);
    }

  grub_ieee1275_finddevice (hba_name, &root);
  grub_ieee1275_get_integer_property (root, "#address-cells", &address_cells,
                                      sizeof address_cells, 0);
  device_type = grub_ieee1275_get_device_type (hba_name);

  if ((grub_strcmp (device_type, "scsi-2") == 0) ||
      (grub_strcmp (device_type, "scsi-sas") == 0))
    {
      if (address_cells == 4)
        {
          if (grub_ieee1275_set_sas_address (ihandle, disk_name, lun) == 0)
            if (grub_ieee1275_no_data_command (ihandle, &ofdisk_tur,
                                               &result) == 0)
              if (result == 0)
                rval = GRUB_ERR_BAD_DEVICE;
        }
      else if ((address_cells == 2) && (grub_isxdigit (*disk_name)))
        {
          grub_uint32_t tgt;
          tgt = grub_strtol (disk_name, 0, 16);
          if (tgt <= 0xff)
            if (grub_ieee1275_set_address (ihandle, tgt, lun) == 0)
              if (grub_ieee1275_no_data_command (ihandle, &ofdisk_tur,
                                                 &result) == 0)
                if (result == 0)
                  rval = GRUB_ERR_BAD_DEVICE;
        }
    }
  else if (grub_strcmp (device_type, "scsi-usb") == 0)
    {
      if (grub_ieee1275_set_address (ihandle, 0, 0) == 0)
        if (grub_ieee1275_no_data_command (ihandle, &ofdisk_tur, &result) == 0)
          if (result == 0)
            rval = GRUB_ERR_BAD_DEVICE;
    }
  else
    {
      /* ieee1275_finddevice would validate these already */
      rval = GRUB_ERR_BAD_DEVICE;
    }

  grub_free (hba_name);
  grub_free (disk_name);
  return rval;
}
#endif
