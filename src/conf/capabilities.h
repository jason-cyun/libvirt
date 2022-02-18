/*
 * capabilities.h: hypervisor capabilities
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_CAPABILITIES_H
# define __VIR_CAPABILITIES_H

# include "internal.h"
# include "virbuffer.h"
# include "cpu_conf.h"
# include "virarch.h"
# include "virmacaddr.h"
# include "virobject.h"
# include "virresctrl.h"

# include <libxml/xpath.h>

typedef struct _virCapsGuestFeature virCapsGuestFeature;
typedef virCapsGuestFeature *virCapsGuestFeaturePtr;
struct _virCapsGuestFeature {
    /*
     * $45 = {
     *   name = 0x7fd2500069a0 "acpi",
     *   defaultOn = true,
     *   toggle = true
     * }
    */
    char *name;
    bool defaultOn;
    bool toggle;
};

typedef struct _virCapsGuestMachine virCapsGuestMachine;
typedef virCapsGuestMachine *virCapsGuestMachinePtr;
struct _virCapsGuestMachine {
    char *name;
    char *canonical;
    unsigned int maxCpus;
};

typedef struct _virCapsGuestDomainInfo virCapsGuestDomainInfo;
typedef virCapsGuestDomainInfo *virCapsGuestDomainInfoPtr;
struct _virCapsGuestDomainInfo {
    char *emulator;
    char *loader;
    int nmachines;
    /* machines means spefic machine type
     * like: "pc-i440fx-rhel7.6.0", "pc-i440fx-rhel7.0.0" etc
     *
     * >>> p *driver->caps->guests[17]->arch->domains[1]->info->machines[1]
     * $56 = {
     *   name = 0x7fd2500063f0 "pc",
     *   canonical = 0x7fd250006410 "pc-i440fx-rhel7.6.0",
     *   maxCpus = 240
     * }
     * >>> p *driver->caps->guests[17]->arch->domains[1]->info->machines[2]
     * $57 = {
     *   name = 0x7fd250006450 "pc-i440fx-rhel7.0.0",
     *   canonical = 0x0,
     *   maxCpus = 240
     * }
     */
    virCapsGuestMachinePtr *machines;
};

typedef struct _virCapsGuestDomain virCapsGuestDomain;
typedef virCapsGuestDomain *virCapsGuestDomainPtr;
struct _virCapsGuestDomain {
    /* domain type means hypervisor
     * VIR_DOMAIN_VIRT_QEMU
     * VIR_DOMAIN_VIRT_KVM
     * VIR_DOMAIN_VIRT_XEN
     * VIR_DOMAIN_VIRT_VMWARE
     * etc
     */
    /*
     * type = 3,
     * info = {
     *   emulator = 0x7fd250006380 "/usr/libexec/qemu-kvm",
     *   loader = 0x0,
     *   nmachines = 20,
     *   machines = 0x7fd2500068f0
     * }
     */
    int type; /* virDomainVirtType */
    virCapsGuestDomainInfo info;
};

typedef struct _virCapsGuestArch virCapsGuestArch;
typedef virCapsGuestArch *virCapsGuestArchptr;
struct _virCapsGuestArch {
    virArch id;
    unsigned int wordsize;
    virCapsGuestDomainInfo defaultInfo;
    // For this arch what domain type we supports
    // VIR_DOMAIN_VIRT_QEMU, VIR_DOMAIN_VIRT_KVM, VIR_DOMAIN_VIRT_VMWARE
    // then under that domain type what specific machine we supports.
    size_t ndomains;
    size_t ndomains_max;
    virCapsGuestDomainPtr *domains;
};

typedef struct _virCapsGuest virCapsGuest;
typedef virCapsGuest *virCapsGuestPtr;
struct _virCapsGuest {
    // qemu supports caps of guest(x86,arm) and features supported for this guest
    // Examples:
    /*
     * $41 = {
     *   ostype = 0,
     *   arch = {
     *     id = VIR_ARCH_X86_64,
     *     wordsize = 64,
     *     defaultInfo = {
     *       emulator = 0x7fd250005ac0 "/usr/bin/qemu-system-x86_64",
     *       loader = 0x0,
     *       nmachines = 23,
     *       machines = 0x7fd250006160
     *     },
     *     ndomains = 2,
     *     ndomains_max = 2,
     *     domains = 0x7fd250006310
     *   },
     *   nfeatures = 5,
     *   nfeatures_max = 6,
     *   features = 0x7fd250005b60
     * }
     */
    int ostype;
    virCapsGuestArch arch;
    size_t nfeatures;
    size_t nfeatures_max;
    virCapsGuestFeaturePtr *features;
};

typedef struct _virCapsHostNUMACellCPU virCapsHostNUMACellCPU;
typedef virCapsHostNUMACellCPU *virCapsHostNUMACellCPUPtr;
struct _virCapsHostNUMACellCPU {
    unsigned int id;
    unsigned int socket_id;
    unsigned int core_id;
    virBitmapPtr siblings;
};

typedef struct _virCapsHostNUMACellSiblingInfo virCapsHostNUMACellSiblingInfo;
typedef virCapsHostNUMACellSiblingInfo *virCapsHostNUMACellSiblingInfoPtr;
struct _virCapsHostNUMACellSiblingInfo {
    int node;               /* foreign NUMA node */
    unsigned int distance;  /* distance to the node */
};

typedef struct _virCapsHostNUMACellPageInfo virCapsHostNUMACellPageInfo;
typedef virCapsHostNUMACellPageInfo *virCapsHostNUMACellPageInfoPtr;
struct _virCapsHostNUMACellPageInfo {
    unsigned int size;      /* page size in kibibytes */
    unsigned long long avail;           /* the size of pool */
};

typedef struct _virCapsHostNUMACell virCapsHostNUMACell;
typedef virCapsHostNUMACell *virCapsHostNUMACellPtr;
struct _virCapsHostNUMACell {
    int num;
    int ncpus;
    unsigned long long mem; /* in kibibytes */
    virCapsHostNUMACellCPUPtr cpus;
    int nsiblings;
    virCapsHostNUMACellSiblingInfoPtr siblings;
    int npageinfo;
    virCapsHostNUMACellPageInfoPtr pageinfo;
};

typedef struct _virCapsHostSecModelLabel virCapsHostSecModelLabel;
typedef virCapsHostSecModelLabel *virCapsHostSecModelLabelPtr;
struct _virCapsHostSecModelLabel {
    char *type;
    char *label;
};

typedef struct _virCapsHostSecModel virCapsHostSecModel;
typedef virCapsHostSecModel *virCapsHostSecModelPtr;
struct _virCapsHostSecModel {
    char *model;
    char *doi;
    size_t nlabels;
    virCapsHostSecModelLabelPtr labels;
};

typedef struct _virCapsHostCacheBank virCapsHostCacheBank;
typedef virCapsHostCacheBank *virCapsHostCacheBankPtr;
struct _virCapsHostCacheBank {
    unsigned int id;
    unsigned int level; /* 1=L1, 2=L2, 3=L3, etc. */
    unsigned long long size; /* B */
    virCacheType type;  /* Data, Instruction or Unified */
    virBitmapPtr cpus;  /* All CPUs that share this bank */
    size_t ncontrols;
    virResctrlInfoPerCachePtr *controls;
};

typedef struct _virCapsHost virCapsHost;
typedef virCapsHost *virCapsHostPtr;
// Caps of host that runs libvirtds
struct _virCapsHost {
    virArch arch;
    size_t nfeatures;
    size_t nfeatures_max;
    char **features;
    /* host info */
    unsigned int powerMgmt;    /* Bitmask of the PM capabilities.
                                * See enum virHostPMCapability.
                                */
    /* host migrate caps
     * trans: tcp, rdma
     */
    bool offlineMigrate;
    bool liveMigrate;
    size_t nmigrateTrans;
    size_t nmigrateTrans_max;
    char **migrateTrans;

    size_t nnumaCell;
    size_t nnumaCell_max;
    virCapsHostNUMACellPtr *numaCell;

    virResctrlInfoPtr resctrl;

    size_t ncaches;
    virCapsHostCacheBankPtr *caches;

    size_t nsecModels;
    virCapsHostSecModelPtr secModels;

    char *netprefix;
    virCPUDefPtr cpu;
    int nPagesSize;             /* size of pagesSize array */
    unsigned int *pagesSize;    /* page sizes support on the system */
    unsigned char host_uuid[VIR_UUID_BUFLEN];
    bool iommu;
};

typedef int (*virDomainDefNamespaceParse)(xmlDocPtr, xmlNodePtr,
                                          xmlXPathContextPtr, void **);
typedef void (*virDomainDefNamespaceFree)(void *);
typedef int (*virDomainDefNamespaceXMLFormat)(virBufferPtr, void *);
typedef const char *(*virDomainDefNamespaceHref)(void);

typedef struct _virDomainXMLNamespace virDomainXMLNamespace;
typedef virDomainXMLNamespace *virDomainXMLNamespacePtr;
struct _virDomainXMLNamespace {
    virDomainDefNamespaceParse parse;
    virDomainDefNamespaceFree free;
    virDomainDefNamespaceXMLFormat format;
    virDomainDefNamespaceHref href;
};

typedef struct _virCaps virCaps;
typedef virCaps *virCapsPtr;
struct _virCaps {
    virObject parent;

    // caps of current host that qemu runs
    virCapsHost host;
    // ALL libvirtd supported guests(arm, x86 and its features)
    size_t nguests;
    size_t nguests_max;
    virCapsGuestPtr *guests;
};

typedef struct _virCapsDomainData virCapsDomainData;
typedef virCapsDomainData *virCapsDomainDataPtr;
struct _virCapsDomainData {
    int ostype;
    int arch;
    int domaintype; /* virDomainVirtType */
    const char *emulator;
    const char *machinetype;
};


virCapsPtr
virCapabilitiesNew(virArch hostarch,
                   bool offlineMigrate,
                   bool liveMigrate);

void
virCapabilitiesFreeNUMAInfo(virCapsPtr caps);

int
virCapabilitiesAddHostFeature(virCapsPtr caps,
                              const char *name);

int
virCapabilitiesAddHostMigrateTransport(virCapsPtr caps,
                                       const char *name);

int
virCapabilitiesSetNetPrefix(virCapsPtr caps,
                            const char *prefix);

int
virCapabilitiesAddHostNUMACell(virCapsPtr caps,
                               int num,
                               unsigned long long mem,
                               int ncpus,
                               virCapsHostNUMACellCPUPtr cpus,
                               int nsiblings,
                               virCapsHostNUMACellSiblingInfoPtr siblings,
                               int npageinfo,
                               virCapsHostNUMACellPageInfoPtr pageinfo);


int
virCapabilitiesSetHostCPU(virCapsPtr caps,
                          virCPUDefPtr cpu);


virCapsGuestMachinePtr *
virCapabilitiesAllocMachines(const char *const *names,
                             int nnames);
void
virCapabilitiesFreeMachines(virCapsGuestMachinePtr *machines,
                            int nmachines);

void
virCapabilitiesFreeGuest(virCapsGuestPtr guest);

virCapsGuestPtr
virCapabilitiesAddGuest(virCapsPtr caps,
                        int ostype,
                        virArch arch,
                        const char *emulator,
                        const char *loader,
                        int nmachines,
                        virCapsGuestMachinePtr *machines);

virCapsGuestDomainPtr
virCapabilitiesAddGuestDomain(virCapsGuestPtr guest,
                              int hvtype,
                              const char *emulator,
                              const char *loader,
                              int nmachines,
                              virCapsGuestMachinePtr *machines);

virCapsGuestFeaturePtr
virCapabilitiesAddGuestFeature(virCapsGuestPtr guest,
                               const char *name,
                               bool defaultOn,
                               bool toggle);

int
virCapabilitiesHostSecModelAddBaseLabel(virCapsHostSecModelPtr secmodel,
                                        const char *type,
                                        const char *label);

virCapsDomainDataPtr
virCapabilitiesDomainDataLookup(virCapsPtr caps,
                                int ostype,
                                virArch arch,
                                int domaintype,
                                const char *emulator,
                                const char *machinetype);

void
virCapabilitiesClearHostNUMACellCPUTopology(virCapsHostNUMACellCPUPtr cpu,
                                            size_t ncpus);

char *
virCapabilitiesFormatXML(virCapsPtr caps);

virBitmapPtr virCapabilitiesGetCpusForNodemask(virCapsPtr caps,
                                               virBitmapPtr nodemask);

int virCapabilitiesGetNodeInfo(virNodeInfoPtr nodeinfo);

int virCapabilitiesInitPages(virCapsPtr caps);

int virCapabilitiesInitNUMA(virCapsPtr caps);

bool virCapsHostCacheBankEquals(virCapsHostCacheBankPtr a,
                                virCapsHostCacheBankPtr b);
void virCapsHostCacheBankFree(virCapsHostCacheBankPtr ptr);

int virCapabilitiesInitCaches(virCapsPtr caps);

void virCapabilitiesHostInitIOMMU(virCapsPtr caps);

#endif /* __VIR_CAPABILITIES_H */
