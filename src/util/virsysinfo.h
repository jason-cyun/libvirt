/*
 * virsysinfo.h: get SMBIOS/sysinfo information from the host
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2010 Daniel Veillard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_SYSINFOS_H__
# define __VIR_SYSINFOS_H__

# include "internal.h"
# include "virutil.h"
# include "virbuffer.h"

typedef enum {
    VIR_SYSINFO_SMBIOS,

    VIR_SYSINFO_LAST
} virSysinfoType;

typedef struct _virSysinfoProcessorDef virSysinfoProcessorDef;
typedef virSysinfoProcessorDef *virSysinfoProcessorDefPtr;
struct _virSysinfoProcessorDef {
    char *processor_socket_destination;
    char *processor_type;
    char *processor_family;
    char *processor_manufacturer;
    char *processor_signature;
    char *processor_version;
    char *processor_external_clock;
    char *processor_max_speed;
    char *processor_status;
    char *processor_serial_number;
    char *processor_part_number;
};

typedef struct _virSysinfoMemoryDef virSysinfoMemoryDef;
typedef virSysinfoMemoryDef *virSysinfoMemoryDefPtr;
struct _virSysinfoMemoryDef {
    char *memory_size;
    char *memory_form_factor;
    char *memory_locator;
    char *memory_bank_locator;
    char *memory_type;
    char *memory_type_detail;
    char *memory_speed;
    char *memory_manufacturer;
    char *memory_serial_number;
    char *memory_part_number;
};

typedef struct _virSysinfoBIOSDef virSysinfoBIOSDef;
typedef virSysinfoBIOSDef *virSysinfoBIOSDefPtr;
struct _virSysinfoBIOSDef {
    /*
     * <sysinfo type='smbios'>
     *   <bios>
     *     <entry name='vendor'>LENOVO</entry>
     *   </bios>
     */
    char *vendor;
    char *version;
    char *date;
    char *release;
};

typedef struct _virSysinfoSystemDef virSysinfoSystemDef;
typedef virSysinfoSystemDef *virSysinfoSystemDefPtr;
struct _virSysinfoSystemDef {
    /*
     * <sysinfo type='smbios'>
     *   <system>
     *     <entry name='manufacturer'>Fedora</entry>
     *     <entry name='product'>Virt-Manager</entry>
     *     <entry name='version'>0.9.4</entry>
     *   </system>
     */
    char *manufacturer;
    char *product;
    char *version;
    char *serial;
    char *uuid;
    char *sku;
    char *family;
};

typedef struct _virSysinfoBaseBoardDef virSysinfoBaseBoardDef;
typedef virSysinfoBaseBoardDef *virSysinfoBaseBoardDefPtr;
struct _virSysinfoBaseBoardDef {
    /*
     * <sysinfo type="smbios">
     *   <baseBoard>
     *     <entry name='manufacturer'>LENOVO</entry>
     *     <entry name='product'>20BE0061MC</entry>
     *     <entry name='version'>0B98401 Pro</entry>
     *     <entry name='serial'>W1KS427111E</entry>
     *   </baseBoard>
     */

    char *manufacturer;
    char *product;
    char *version;
    char *serial;
    char *asset;
    char *location;
    /* XXX board type */
};

typedef struct _virSysinfoChassisDef virSysinfoChassisDef;
typedef virSysinfoChassisDef *virSysinfoChassisDefPtr;
struct _virSysinfoChassisDef {
    /*
     * <sysinfo type='smbios'>
     *   <chassis>
     *     <entry name='manufacturer'>Dell Inc.</entry>
     *     <entry name='version'>2.12</entry>
     *     <entry name='serial'>65X0XF2</entry>
     *     <entry name='asset'>40000101</entry>
     *     <entry name='sku'>Type3Sku1</entry>
     *   </chassis>
     */
    char *manufacturer;
    char *version;
    char *serial;
    char *asset;
    char *sku;
};

typedef struct _virSysinfoOEMStringsDef virSysinfoOEMStringsDef;
typedef virSysinfoOEMStringsDef *virSysinfoOEMStringsDefPtr;
struct _virSysinfoOEMStringsDef {
    /*
     * <sysinfo type='smbios'>
     *   <oemStrings>
     *     <entry>myappname:some arbitrary data</entry>
     *     <entry>otherappname:more arbitrary data</entry>
     *   </oemStrings>
     */
    size_t nvalues;
    char **values;
};

typedef struct _virSysinfoDef virSysinfoDef;
typedef virSysinfoDef *virSysinfoDefPtr;
struct _virSysinfoDef {
    /*
     *
     * <os>
     *   <smbios mode='sysinfo'/>
     *   ...
     * </os>
     * <sysinfo type='smbios'>
     *   <bios>
     *     <entry name='vendor'>LENOVO</entry>
     *   </bios>
     *   <system>
     *     <entry name='manufacturer'>Fedora</entry>
     *     <entry name='product'>Virt-Manager</entry>
     *     <entry name='version'>0.9.4</entry>
     *   </system>
     *   <baseBoard>
     *     <entry name='manufacturer'>LENOVO</entry>
     *     <entry name='product'>20BE0061MC</entry>
     *     <entry name='version'>0B98401 Pro</entry>
     *     <entry name='serial'>W1KS427111E</entry>
     *   </baseBoard>
     *   <chassis>
     *     <entry name='manufacturer'>Dell Inc.</entry>
     *     <entry name='version'>2.12</entry>
     *     <entry name='serial'>65X0XF2</entry>
     *     <entry name='asset'>40000101</entry>
     *     <entry name='sku'>Type3Sku1</entry>
     *   </chassis>
     *   <oemStrings>
     *     <entry>myappname:some arbitrary data</entry>
     *     <entry>otherappname:more arbitrary data</entry>
     *   </oemStrings>
     * </sysinfo>
     */
    int type;

    virSysinfoBIOSDefPtr bios;
    virSysinfoSystemDefPtr system;

    size_t nbaseBoard;
    virSysinfoBaseBoardDefPtr baseBoard;

    virSysinfoChassisDefPtr chassis;

    size_t nprocessor;
    virSysinfoProcessorDefPtr processor;

    size_t nmemory;
    virSysinfoMemoryDefPtr memory;

    virSysinfoOEMStringsDefPtr oemStrings;
};

virSysinfoDefPtr virSysinfoRead(void);

void virSysinfoBIOSDefFree(virSysinfoBIOSDefPtr def);
void virSysinfoSystemDefFree(virSysinfoSystemDefPtr def);
void virSysinfoBaseBoardDefClear(virSysinfoBaseBoardDefPtr def);
void virSysinfoChassisDefFree(virSysinfoChassisDefPtr def);
void virSysinfoOEMStringsDefFree(virSysinfoOEMStringsDefPtr def);
void virSysinfoDefFree(virSysinfoDefPtr def);

int virSysinfoFormat(virBufferPtr buf, virSysinfoDefPtr def)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool virSysinfoIsEqual(virSysinfoDefPtr src,
                       virSysinfoDefPtr dst);

VIR_ENUM_DECL(virSysinfo)

#endif /* __VIR_SYSINFOS_H__ */
