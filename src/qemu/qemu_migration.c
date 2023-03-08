/*
 * qemu_migration.c: QEMU migration handling
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 */

#include <config.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>

#include "qemu_migration.h"
#include "qemu_migration_cookie.h"
#include "qemu_migration_params.h"
#include "qemu_monitor.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "qemu_capabilities.h"
#include "qemu_alias.h"
#include "qemu_cgroup.h"
#include "qemu_hotplug.h"
#include "qemu_blockjob.h"
#include "qemu_security.h"
#include "qemu_block.h"

#include "domain_audit.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virnetdevopenvswitch.h"
#include "datatypes.h"
#include "virfdstream.h"
#include "viruuid.h"
#include "virtime.h"
#include "locking/domain_lock.h"
#include "rpc/virnetsocket.h"
#include "virstoragefile.h"
#include "viruri.h"
#include "virhook.h"
#include "virstring.h"
#include "virtypedparam.h"
#include "virprocess.h"
#include "nwfilter_conf.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_migration");

VIR_ENUM_IMPL(qemuMigrationJobPhase, QEMU_MIGRATION_PHASE_LAST,
              "none",
              "perform2",
              "begin3",
              "perform3",
              "perform3_done",
              "confirm3_cancelled",
              "confirm3",
              "prepare",
              "finish2",
              "finish3",
);

static int
qemuMigrationJobStart(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      qemuDomainAsyncJob job,
                      unsigned long apiFlags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

static void
qemuMigrationJobSetPhase(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuMigrationJobPhase phase)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

static void
qemuMigrationJobStartPhase(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           qemuMigrationJobPhase phase)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

static void
qemuMigrationJobContinue(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);

static bool
qemuMigrationJobIsActive(virDomainObjPtr vm,
                         qemuDomainAsyncJob job)
    ATTRIBUTE_NONNULL(1);

static void
qemuMigrationJobFinish(virQEMUDriverPtr driver,
                       virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

static void
qemuMigrationSrcStoreDomainState(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    priv->preMigrationState = virDomainObjGetState(vm, NULL);

    VIR_DEBUG("Storing pre-migration state=%d domain=%p",
              priv->preMigrationState, vm);
}

/* Returns true if the domain was resumed, false otherwise */
static bool
qemuMigrationSrcRestoreDomainState(virQEMUDriverPtr driver, virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int reason;
    virDomainState state = virDomainObjGetState(vm, &reason);
    bool ret = false;

    VIR_DEBUG("driver=%p, vm=%p, pre-mig-state=%s, state=%s, reason=%s",
              driver, vm,
              virDomainStateTypeToString(priv->preMigrationState),
              virDomainStateTypeToString(state),
              virDomainStateReasonToString(state, reason));

    if (state != VIR_DOMAIN_PAUSED ||
        reason == VIR_DOMAIN_PAUSED_POSTCOPY_FAILED)
        goto cleanup;

    // go here means state is PAUSED or reason == VIR_DOMAIN_PAUSED_POSTCOPY_FAILED
    // we should resume vm if it's running before!!!
    if (priv->preMigrationState == VIR_DOMAIN_RUNNING) {
        /* This is basically the only restore possibility that's safe
         * and we should attempt to do */

        VIR_DEBUG("Restoring pre-migration state due to migration error");

        /* we got here through some sort of failure; start the domain again */
        if (qemuProcessStartCPUs(driver, vm,
                                 VIR_DOMAIN_RUNNING_MIGRATION_CANCELED,
                                 QEMU_ASYNC_JOB_MIGRATION_OUT) < 0) {
            /* Hm, we already know we are in error here.  We don't want to
             * overwrite the previous error, though, so we just throw something
             * to the logs and hope for the best */
            VIR_ERROR(_("Failed to resume guest %s after failure"), vm->def->name);
            goto cleanup;
        }
        ret = true;
    }

 cleanup:
    priv->preMigrationState = VIR_DOMAIN_NOSTATE;
    return ret;
}


static int
qemuMigrationDstPrecreateDisk(virConnectPtr conn,
                              virDomainDiskDefPtr disk,
                              unsigned long long capacity)
{
    int ret = -1;
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    char *volName = NULL, *basePath = NULL;
    char *volStr = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *format = NULL;
    unsigned int flags = 0;

    VIR_DEBUG("Precreate disk type=%s", virStorageTypeToString(disk->src->type));

    switch ((virStorageType)disk->src->type) {
    case VIR_STORAGE_TYPE_FILE:
        if (!virDomainDiskGetSource(disk)) {
            VIR_DEBUG("Dropping sourceless disk '%s'",
                      disk->dst);
            return 0;
        }

        if (VIR_STRDUP(basePath, disk->src->path) < 0)
            goto cleanup;

        if (!(volName = strrchr(basePath, '/'))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("malformed disk path: %s"),
                           disk->src->path);
            goto cleanup;
        }

        *volName = '\0';
        volName++;

        if (!(pool = virStoragePoolLookupByTargetPath(conn, basePath)))
            goto cleanup;
        format = virStorageFileFormatTypeToString(disk->src->format);
        if (disk->src->format == VIR_STORAGE_FILE_QCOW2)
            flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;
        break;

    case VIR_STORAGE_TYPE_VOLUME:
        if (!(pool = virStoragePoolLookupByName(conn, disk->src->srcpool->pool)))
            goto cleanup;
        format = virStorageFileFormatTypeToString(disk->src->format);
        volName = disk->src->srcpool->volume;
        if (disk->src->format == VIR_STORAGE_FILE_QCOW2)
            flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        VIR_DEBUG("Skipping creation of network disk '%s'",
                  disk->dst);
        return 0;

    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot precreate storage for disk type '%s'"),
                       virStorageTypeToString(disk->src->type));
        goto cleanup;
    }

    if ((vol = virStorageVolLookupByName(pool, volName))) {
        VIR_DEBUG("Skipping creation of already existing volume of name '%s'",
                  volName);
        ret = 0;
        goto cleanup;
    }

    virBufferAddLit(&buf, "<volume>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", volName);
    virBufferAsprintf(&buf, "<capacity>%llu</capacity>\n", capacity);
    virBufferAddLit(&buf, "<target>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferAsprintf(&buf, "<format type='%s'/>\n", format);
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</target>\n");
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</volume>\n");

    if (!(volStr = virBufferContentAndReset(&buf))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to create volume XML"));
        goto cleanup;
    }

    if (!(vol = virStorageVolCreateXML(pool, volStr, flags)))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(basePath);
    VIR_FREE(volStr);
    virObjectUnref(vol);
    virObjectUnref(pool);
    return ret;
}

static bool
qemuMigrationAnyCopyDisk(virDomainDiskDef const *disk,
                         size_t nmigrate_disks, const char **migrate_disks)
{
    size_t i;

    /* Check if the disk alias is in the list */
    if (nmigrate_disks) {
        for (i = 0; i < nmigrate_disks; i++) {
            if (STREQ(disk->dst, migrate_disks[i]))
                return true;
        }
        return false;
    }

    /* Default is to migrate only non-shared non-readonly disks
     * with source */
    return !disk->src->shared && !disk->src->readonly &&
           !virStorageSourceIsEmpty(disk->src);
}


static int
qemuMigrationDstPrecreateStorage(virDomainObjPtr vm,
                                 qemuMigrationCookieNBDPtr nbd,
                                 size_t nmigrate_disks,
                                 const char **migrate_disks,
                                 bool incremental)
{
    int ret = -1;
    size_t i = 0;
    virConnectPtr conn;

    if (!nbd || !nbd->ndisks)
        return 0;

    if (!(conn = virGetConnectStorage()))
        return -1;

    for (i = 0; i < nbd->ndisks; i++) {
        virDomainDiskDefPtr disk;
        const char *diskSrcPath;

        VIR_DEBUG("Looking up disk target '%s' (capacity=%llu)",
                  nbd->disks[i].target, nbd->disks[i].capacity);

        if (!(disk = virDomainDiskByName(vm->def, nbd->disks[i].target,
                                         false))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to find disk by target: %s"),
                           nbd->disks[i].target);
            goto cleanup;
        }

        diskSrcPath = virDomainDiskGetSource(disk);

        /* Skip disks we don't want to migrate and already existing disks. */
        if (!qemuMigrationAnyCopyDisk(disk, nmigrate_disks, migrate_disks) ||
            (diskSrcPath && virFileExists(diskSrcPath))) {
            continue;
        }

        if (incremental) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("pre-creation of storage targets for incremental "
                             "storage migration is not supported"));
            goto cleanup;
        }

        VIR_DEBUG("Proceeding with disk source %s", NULLSTR(diskSrcPath));

        if (qemuMigrationDstPrecreateDisk(conn, disk, nbd->disks[i].capacity) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(conn);
    return ret;
}


/**
 * qemuMigrationDstStartNBDServer:
 * @driver: qemu driver
 * @vm: domain
 *
 * Starts NBD server. This is a newer method to copy
 * storage during migration than using 'blk' and 'inc'
 * arguments in 'migrate' monitor command.
 * Error is reported here.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
qemuMigrationDstStartNBDServer(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               const char *listenAddr,
                               size_t nmigrate_disks,
                               const char **migrate_disks,
                               int nbdPort,
                               const char *tls_alias)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned short port = 0;
    char *diskAlias = NULL;
    size_t i;

    if (nbdPort < 0 || nbdPort > USHRT_MAX) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("nbd port must be in range 0-65535"));
        return -1;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

        /* check whether disk should be migrated */
        if (!qemuMigrationAnyCopyDisk(disk, nmigrate_disks, migrate_disks))
            continue;

        if (disk->src->readonly || virStorageSourceIsEmpty(disk->src)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("Cannot migrate empty or read-only disk %s"),
                           disk->dst);
            goto cleanup;
        }

        VIR_FREE(diskAlias);
        if (!(diskAlias = qemuAliasDiskDriveFromDisk(disk)))
            goto cleanup;

        if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
            goto cleanup;

        if (port == 0) {
            // start one nbd server at qemu by QMP command
            if (nbdPort)
                port = nbdPort;
            else if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
                goto exit_monitor;

            /* qmp: nbd-server-start
             * Start an NBD server listening on the given host and port.
             * Block devices can then be exported using nbd-server-add
             *
             * qmp: nbd-server-add
             * Export a block node to QEMU’s embedded NBD server.
             */
            if (qemuMonitorNBDServerStart(priv->mon, listenAddr, port, tls_alias) < 0)
                goto exit_monitor;
        }

        // add each migrating disk to nbd server
        if (qemuMonitorNBDServerAdd(priv->mon, diskAlias, true) < 0)
            goto exit_monitor;
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;
    }

    // nbd server port that qemu listen on for non-shared disk migration
    priv->nbdPort = port;
    ret = 0;

 cleanup:
    VIR_FREE(diskAlias);
    if (ret < 0 && nbdPort == 0)
        virPortAllocatorRelease(port);
    return ret;

 exit_monitor:
    ignore_value(qemuDomainObjExitMonitor(driver, vm));
    goto cleanup;
}


static int
qemuMigrationDstStopNBDServer(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              qemuMigrationCookiePtr mig)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!mig->nbd)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        return -1;

    if (qemuMonitorNBDServerStop(priv->mon) < 0)
        VIR_WARN("Unable to stop NBD server");
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;

    virPortAllocatorRelease(priv->nbdPort);
    priv->nbdPort = 0;
    return 0;
}


/**
 * qemuMigrationSrcNBDStorageCopyReady:
 * @vm: domain
 *
 * Check the status of all drives copied via qemuMigrationSrcNBDStorageCopy.
 * Any pending block job events for the mirrored disks will be processed.
 *
 * Returns 1 if all mirrors are "ready",
 *         0 if some mirrors are still performing initial sync,
 *        -1 on error.
 */
static int
qemuMigrationSrcNBDStorageCopyReady(virDomainObjPtr vm,
                                    qemuDomainAsyncJob asyncJob)
{
    size_t i;
    size_t notReady = 0;
    int status;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        char *error = NULL;

        if (!diskPriv->migrating)
            continue;

        status = qemuBlockJobUpdate(vm, asyncJob, disk, &error);
        if (status == VIR_DOMAIN_BLOCK_JOB_FAILED) {
            if (error) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("migration of disk %s failed: %s"),
                               disk->dst, error);
                VIR_FREE(error);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("migration of disk %s failed"), disk->dst);
            }
            return -1;
        }
        VIR_FREE(error);

        if (disk->mirrorState != VIR_DOMAIN_DISK_MIRROR_STATE_READY)
            notReady++;
    }

    if (notReady) {
        VIR_DEBUG("Waiting for %zu disk mirrors to get ready", notReady);
        return 0;
    } else {
        VIR_DEBUG("All disk mirrors are ready");
        return 1;
    }
}


/*
 * If @check is true, the function will report an error and return a different
 * code in case a block job fails. This way we can properly abort migration in
 * case some block jobs failed once all memory has already been transferred.
 *
 * Returns 1 if all mirrors are gone,
 *         0 if some mirrors are still active,
 *         -1 some mirrors failed but some are still active,
 *         -2 all mirrors are gone but some of them failed.
 */
static int
qemuMigrationSrcNBDCopyCancelled(virDomainObjPtr vm,
                                 qemuDomainAsyncJob asyncJob,
                                 bool check)
{
    size_t i;
    size_t active = 0;
    size_t completed = 0;
    int status;
    bool failed = false;

 retry:
    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        char *error = NULL;

        if (!diskPriv->migrating)
            continue;

        status = qemuBlockJobUpdate(vm, asyncJob, disk, &error);
        switch (status) {
        case VIR_DOMAIN_BLOCK_JOB_FAILED:
            if (check) {
                if (error) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("migration of disk %s failed: %s"),
                                   disk->dst, error);
                } else {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("migration of disk %s failed"), disk->dst);
                }
                failed = true;
            }
            ATTRIBUTE_FALLTHROUGH;
        case VIR_DOMAIN_BLOCK_JOB_CANCELED:
        case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
            qemuBlockJobSyncEnd(vm, asyncJob, disk);
            diskPriv->migrating = false;
            break;

        default:
            active++;
        }

        if (status == VIR_DOMAIN_BLOCK_JOB_COMPLETED)
            completed++;

        VIR_FREE(error);
    }

    /* Updating completed block job drops the lock thus we have to recheck
     * block jobs for disks that reside before the disk(s) with completed
     * block job.
     */
    if (completed > 0) {
        completed = 0;
        active = 0;
        goto retry;
    }

    if (failed) {
        if (active) {
            VIR_DEBUG("Some disk mirrors failed; still waiting for %zu "
                      "disk mirrors to finish", active);
            return -1;
        } else {
            VIR_DEBUG("All disk mirrors are gone; some of them failed");
            return -2;
        }
    } else {
        if (active) {
            VIR_DEBUG("Waiting for %zu disk mirrors to finish", active);
            return 0;
        } else {
            VIR_DEBUG("All disk mirrors are gone");
            return 1;
        }
    }
}


/*
 * Returns 0 on success,
 *         1 when job is already completed or it failed and failNoJob is false,
 *         -1 on error or when job failed and failNoJob is true.
 */
static int
qemuMigrationSrcNBDCopyCancelOne(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDiskDefPtr disk,
                                 bool failNoJob,
                                 qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *diskAlias = NULL;
    char *error = NULL;
    int ret = -1;
    int status;
    int rv;

    status = qemuBlockJobUpdate(vm, asyncJob, disk, &error);
    switch (status) {
    case VIR_DOMAIN_BLOCK_JOB_FAILED:
    case VIR_DOMAIN_BLOCK_JOB_CANCELED:
        if (failNoJob) {
            if (error) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("migration of disk %s failed: %s"),
                               disk->dst, error);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("migration of disk %s failed"), disk->dst);
            }
            goto cleanup;
        }
        ATTRIBUTE_FALLTHROUGH;
    case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
        ret = 1;
        goto cleanup;
    }

    if (!(diskAlias = qemuAliasDiskDriveFromDisk(disk)))
        return -1;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    rv = qemuMonitorBlockJobCancel(priv->mon, diskAlias);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rv < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(diskAlias);
    VIR_FREE(error);
    return ret;
}


/**
 * qemuMigrationSrcNBDCopyCancel:
 * @driver: qemu driver
 * @vm: domain
 * @check: if true report an error when some of the mirrors fails
 *
 * Cancel all drive-mirrors started by qemuMigrationSrcNBDStorageCopy.
 * Any pending block job events for the affected disks will be processed.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
qemuMigrationSrcNBDCopyCancel(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              bool check,
                              qemuDomainAsyncJob asyncJob,
                              virConnectPtr dconn)
{
    virErrorPtr err = NULL;
    int ret = -1;
    size_t i;
    int rv;
    bool failed = false;

    VIR_DEBUG("Cancelling drive mirrors for domain %s", vm->def->name);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!diskPriv->migrating)
            continue;

        rv = qemuMigrationSrcNBDCopyCancelOne(driver, vm, disk,
                                              check, asyncJob);
        if (rv != 0) {
            if (rv < 0) {
                if (!err)
                    err = virSaveLastError();
                failed = true;
            }
            qemuBlockJobSyncEnd(vm, asyncJob, disk);
            diskPriv->migrating = false;
        }
    }

    while ((rv = qemuMigrationSrcNBDCopyCancelled(vm, asyncJob, check)) != 1) {
        if (check && !failed &&
            dconn && virConnectIsAlive(dconn) <= 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Lost connection to destination host"));
            failed = true;
        }

        if (rv < 0) {
            failed = true;
            if (rv == -2)
                break;
        }

        if (failed && !err)
            err = virSaveLastError();

        // if vm is destroyed, I should be waked up, next time if wait again
        // it will report errro as vm is not active now
        if (virDomainObjWait(vm) < 0)
            goto cleanup;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!diskPriv->migrSource)
            continue;

        qemuBlockStorageSourceDetachOneBlockdev(driver, vm, asyncJob,
                                                diskPriv->migrSource);
        virStorageSourceFree(diskPriv->migrSource);
        diskPriv->migrSource = NULL;
    }

    ret = failed ? -1 : 0;

 cleanup:
    if (err) {
        virSetError(err);
        virFreeError(err);
    }
    return ret;
}


static int
qemuMigrationSrcNBDStorageCopyBlockdev(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virDomainDiskDefPtr disk,
                                       const char *diskAlias,
                                       const char *host,
                                       int port,
                                       unsigned long long mirror_speed,
                                       unsigned int mirror_flags,
                                       const char *tlsAlias)
{
    qemuBlockStorageSourceAttachDataPtr data = NULL;
    qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    virStorageSourcePtr copysrc = NULL;
    int mon_ret = 0;
    int ret = -1;

    VIR_DEBUG("starting blockdev mirror for disk=%s to host=%s", diskAlias, host);

    if (VIR_ALLOC(copysrc) < 0)
        goto cleanup;

    copysrc->type = VIR_STORAGE_TYPE_NETWORK;
    copysrc->protocol = VIR_STORAGE_NET_PROTOCOL_NBD;
    copysrc->format = VIR_STORAGE_FILE_RAW;

    if (VIR_ALLOC(copysrc->backingStore) < 0)
        goto cleanup;

    if (VIR_STRDUP(copysrc->path, diskAlias) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(copysrc->hosts, 1) < 0)
        goto cleanup;

    copysrc->nhosts = 1;
    copysrc->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    copysrc->hosts->port = port;
    if (VIR_STRDUP(copysrc->hosts->name, host) < 0)
        goto cleanup;

    if (VIR_STRDUP(copysrc->tlsAlias, tlsAlias) < 0)
        goto cleanup;

    if (virAsprintf(&copysrc->nodestorage, "migration-%s-storage", disk->dst) < 0 ||
        virAsprintf(&copysrc->nodeformat, "migration-%s-format", disk->dst) < 0)
        goto cleanup;

    if (!(data = qemuBlockStorageSourceAttachPrepareBlockdev(copysrc)))
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    mon_ret = qemuBlockStorageSourceAttachApply(qemuDomainGetMonitor(vm), data);

    if (mon_ret == 0)
        mon_ret = qemuMonitorBlockdevMirror(qemuDomainGetMonitor(vm), NULL,
                                            diskAlias, copysrc->nodeformat,
                                            mirror_speed, 0, 0, mirror_flags);

    if (mon_ret != 0)
        qemuBlockStorageSourceAttachRollback(qemuDomainGetMonitor(vm), data);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || mon_ret < 0)
        goto cleanup;

    VIR_STEAL_PTR(diskPriv->migrSource, copysrc);

    ret = 0;

 cleanup:
    qemuBlockStorageSourceAttachDataFree(data);
    virStorageSourceFree(copysrc);
    return ret;
}


static int
qemuMigrationSrcNBDStorageCopyDriveMirror(virQEMUDriverPtr driver,
                                          virDomainObjPtr vm,
                                          const char *diskAlias,
                                          const char *host,
                                          int port,
                                          unsigned long long mirror_speed,
                                          unsigned int mirror_flags)
{
    char *nbd_dest = NULL;
    int mon_ret;
    int ret = -1;

    if (strchr(host, ':')) {
        if (virAsprintf(&nbd_dest, "nbd:[%s]:%d:exportname=%s",
                        host, port, diskAlias) < 0)
            goto cleanup;
    } else {
        if (virAsprintf(&nbd_dest, "nbd:%s:%d:exportname=%s",
                        host, port, diskAlias) < 0)
            goto cleanup;
    }

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    mon_ret = qemuMonitorDriveMirror(qemuDomainGetMonitor(vm),
                                     diskAlias, nbd_dest, "raw",
                                     mirror_speed, 0, 0, mirror_flags);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || mon_ret < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(nbd_dest);
    return ret;
}


/**
 * qemuMigrationSrcNBDStorageCopy:
 * @driver: qemu driver
 * @vm: domain
 * @mig: migration cookie
 * @host: where are we migrating to
 * @speed: bandwidth limit in MiB/s
 * @migrate_flags: migrate monitor command flags
 *
 * Migrate non-shared storage using the NBD protocol to the server running
 * inside the qemu process on dst and wait until the copy converges.
 * On success update @migrate_flags so we don't tell 'migrate' command
 * to do the very same operation. On failure, the caller is
 * expected to call qemuMigrationSrcNBDCopyCancel to stop all
 * running copy operations.
 *
 * Returns 0 on success (@migrate_flags updated),
 *        -1 otherwise.
 */
static int
qemuMigrationSrcNBDStorageCopy(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               qemuMigrationCookiePtr mig,
                               const char *host,
                               unsigned long speed,
                               unsigned int *migrate_flags,
                               size_t nmigrate_disks,
                               const char **migrate_disks,
                               virConnectPtr dconn,
                               const char *tlsAlias,
                               unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int port;
    size_t i;
    char *diskAlias = NULL;
    unsigned long long mirror_speed = speed;
    unsigned int mirror_flags = VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT;
    int rv;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    VIR_DEBUG("Starting drive mirrors for domain %s", vm->def->name);

    if (mirror_speed > LLONG_MAX >> 20) {
        virReportError(VIR_ERR_OVERFLOW,
                       _("bandwidth must be less than %llu"),
                       LLONG_MAX >> 20);
        goto cleanup;
    }
    mirror_speed <<= 20;

    /* steal NBD port and thus prevent its propagation back to destination */
    port = mig->nbd->port;
    mig->nbd->port = 0;

    if (*migrate_flags & QEMU_MONITOR_MIGRATE_NON_SHARED_INC)
        mirror_flags |= VIR_DOMAIN_BLOCK_REBASE_SHALLOW;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        int rc;

        /* check whether disk should be migrated */
        if (!qemuMigrationAnyCopyDisk(disk, nmigrate_disks, migrate_disks))
            continue;

        if (!(diskAlias = qemuAliasDiskDriveFromDisk(disk)))
            goto cleanup;

        qemuBlockJobSyncBegin(disk);

        if (flags & VIR_MIGRATE_TLS) {
            rc = qemuMigrationSrcNBDStorageCopyBlockdev(driver, vm,
                                                        disk, diskAlias,
                                                        host, port,
                                                        mirror_speed,
                                                        mirror_flags,
                                                        tlsAlias);
        } else {
            rc = qemuMigrationSrcNBDStorageCopyDriveMirror(driver, vm, diskAlias,
                                                           host, port,
                                                           mirror_speed,
                                                           mirror_flags);
        }

        if (rc < 0) {
            qemuBlockJobSyncEnd(vm, QEMU_ASYNC_JOB_MIGRATION_OUT, disk);
            goto cleanup;
        }

        VIR_FREE(diskAlias);
        diskPriv->migrating = true;

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            goto cleanup;
        }
    }

    while ((rv = qemuMigrationSrcNBDStorageCopyReady(vm, QEMU_ASYNC_JOB_MIGRATION_OUT)) != 1) {
        if (rv < 0)
            goto cleanup;

        if (priv->job.abortJob) {
            priv->job.current->status = QEMU_DOMAIN_JOB_STATUS_CANCELED;
            virReportError(VIR_ERR_OPERATION_ABORTED, _("%s: %s"),
                           qemuDomainAsyncJobTypeToString(priv->job.asyncActive),
                           _("canceled by client"));
            goto cleanup;
        }

        if (dconn && virConnectIsAlive(dconn) <= 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Lost connection to destination host"));
            goto cleanup;
        }

        if (virDomainObjWait(vm) < 0)
            goto cleanup;
    }

    qemuMigrationSrcFetchMirrorStats(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                     priv->job.current);

    /* Okay, all disks are ready. Modify migrate_flags */
    *migrate_flags &= ~(QEMU_MONITOR_MIGRATE_NON_SHARED_DISK |
                        QEMU_MONITOR_MIGRATE_NON_SHARED_INC);
    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    VIR_FREE(diskAlias);
    return ret;
}


/**
 * qemuMigrationSrcIsAllowedHostdev:
 * @def: domain definition
 *
 * Checks that @def does not contain any host devices unsupported accross
 * migrations. Returns true if the vm is allowed to migrate.
 */
static bool
qemuMigrationSrcIsAllowedHostdev(const virDomainDef *def)
{
    size_t i;

    /* Migration with USB host devices is allowed, all other devices are
     * forbidden. */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain has assigned non-USB host devices"));
            return false;
        }
    }

    return true;
}


/**
 * qemuMigrationSrcIsAllowed:
 * @driver: qemu driver struct
 * @vm: domain object
 * @remote: migration is remote
 * @flags: migration flags (see struct virDomainMigrateFlags)
 *
 * Validates that the configuration of @vm can be migrated in various
 * situations. If @remote is true, the migration happens to remote host. @flags
 * is used to check various special migration types according to the request.
 *
 * Returns true if migration is supported. Reports libvirt error and returns
 * false otherwise.
 */
bool
qemuMigrationSrcIsAllowed(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          bool remote,
                          unsigned int flags)
{
    int nsnapshots;
    int pauseReason;
    size_t i;

    /* perform these checks only when migrating to remote hosts */
    if (remote) {
        nsnapshots = virDomainSnapshotObjListNum(vm->snapshots, NULL, 0);
        if (nsnapshots < 0)
            return false;

        if (nsnapshots > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("cannot migrate domain with %d snapshots"),
                           nsnapshots);
            return false;
        }

        /* cancel migration if disk I/O error is emitted while migrating */
        if (flags & VIR_MIGRATE_ABORT_ON_ERROR &&
            !(flags & VIR_MIGRATE_OFFLINE) &&
            virDomainObjGetState(vm, &pauseReason) == VIR_DOMAIN_PAUSED &&
            pauseReason == VIR_DOMAIN_PAUSED_IOERROR) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot migrate domain with I/O error"));
            return false;
        }

    }

    /* following checks don't make sense for offline migration */
    /* live migration is not allowed if
     * 1. domain is marked for auto destroy
     * 2. domain has block job
     * 3. domain has non-usb hostdev assigned
     * 4. domain has shared memory
     * 5. more
     */
    if (!(flags & VIR_MIGRATE_OFFLINE)) {
        if (qemuProcessAutoDestroyActive(driver, vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("domain is marked for auto destroy"));
            return false;
        }


        if (qemuDomainHasBlockjob(vm, false)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain has active block job"));
            return false;
        }

        if (!qemuMigrationSrcIsAllowedHostdev(vm->def))
            return false;

        if (vm->def->cpu) {
            /* QEMU blocks migration and save with invariant TSC enabled
             * unless TSC frequency is explicitly set.
             */
            if (virCPUCheckFeature(vm->def->os.arch, vm->def->cpu,
                                   "invtsc") == 1) {
                bool block = true;

                for (i = 0; i < vm->def->clock.ntimers; i++) {
                    virDomainTimerDefPtr timer = vm->def->clock.timers[i];

                    if (timer->name == VIR_DOMAIN_TIMER_NAME_TSC &&
                        timer->frequency > 0) {
                        block = false;
                        break;
                    }
                }

                if (block) {
                    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                                   _("domain has 'invtsc' CPU feature but "
                                     "TSC frequency is not specified"));
                    return false;
                }
            }
        }

        /* Verify that memory device config can be transferred reliably */
        for (i = 0; i < vm->def->nmems; i++) {
            virDomainMemoryDefPtr mem = vm->def->mems[i];

            if (mem->model == VIR_DOMAIN_MEMORY_MODEL_DIMM &&
                mem->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("domain's dimm info lacks slot ID "
                                 "or base address"));

                return false;
            }
        }

        if (vm->def->nshmems) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("migration with shmem device is not supported"));
            return false;
        }
    }

    return true;
}

static bool
qemuMigrationSrcIsSafe(virDomainDefPtr def,
                       size_t nmigrate_disks,
                       const char **migrate_disks,
                       unsigned int flags)

{
    bool storagemigration = flags & (VIR_MIGRATE_NON_SHARED_DISK |
                                     VIR_MIGRATE_NON_SHARED_INC);
    size_t i;
    int rc;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk = def->disks[i];
        const char *src = virDomainDiskGetSource(disk);

        /* Disks without any source (i.e. floppies and CD-ROMs)
         * OR readonly are safe. */
        if (virStorageSourceIsEmpty(disk->src) ||
            disk->src->readonly)
            continue;

        /* Disks which are migrated by qemu are safe too. */
        if (storagemigration &&
            qemuMigrationAnyCopyDisk(disk, nmigrate_disks, migrate_disks))
            continue;

        /* However, disks on local FS (e.g. ext4) are not safe. */
        if (virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_FILE) {
            if ((rc = virFileIsSharedFS(src)) < 0) {
                return false;
            } else if (rc == 0) {
                virReportError(VIR_ERR_MIGRATE_UNSAFE, "%s",
                               _("Migration without shared storage is unsafe"));
                return false;
            }
            if ((rc = virStorageFileIsClusterFS(src)) < 0)
                return false;
            else if (rc == 1)
                continue;
        } else if (disk->src->type == VIR_STORAGE_TYPE_NETWORK &&
                   disk->src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD) {
            continue;
        }

        /* Our code elsewhere guarantees shared disks are either readonly (in
         * which case cache mode doesn't matter) or used with cache=none or used with cache=directsync */
        if (disk->src->shared ||
            disk->cachemode == VIR_DOMAIN_DISK_CACHE_DISABLE ||
            disk->cachemode == VIR_DOMAIN_DISK_CACHE_DIRECTSYNC)
            continue;

        virReportError(VIR_ERR_MIGRATE_UNSAFE, "%s",
                       _("Migration may lead to data corruption if disks"
                         " use cache != none or cache != directsync"));
        return false;
    }

    return true;
}

/** qemuMigrationSrcSetOffline
 * Pause domain for non-live migration.
 */
int
qemuMigrationSrcSetOffline(virQEMUDriverPtr driver,
                           virDomainObjPtr vm)
{
    int ret;
    VIR_DEBUG("driver=%p vm=%p", driver, vm);
    ret = qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_MIGRATION,
                              QEMU_ASYNC_JOB_MIGRATION_OUT);
    if (ret == 0) {
        virObjectEventPtr event;

        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    return ret;
}


void
qemuMigrationAnyPostcopyFailed(virQEMUDriverPtr driver,
                               virDomainObjPtr vm)
{
    virDomainState state;
    int reason;

    state = virDomainObjGetState(vm, &reason);

    if (state != VIR_DOMAIN_PAUSED &&
        state != VIR_DOMAIN_RUNNING)
        return;

    if (state == VIR_DOMAIN_PAUSED &&
        reason == VIR_DOMAIN_PAUSED_POSTCOPY_FAILED)
        return;

    VIR_WARN("Migration of domain %s failed during post-copy; "
             "leaving the domain paused", vm->def->name);

    if (state == VIR_DOMAIN_RUNNING) {
        virObjectEventPtr event;

        if (qemuProcessStopCPUs(driver, vm,
                                VIR_DOMAIN_PAUSED_POSTCOPY_FAILED,
                                QEMU_ASYNC_JOB_MIGRATION_IN) < 0) {
            VIR_WARN("Unable to pause guest CPUs for %s", vm->def->name);
            return;
        }

        event = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_SUSPENDED,
                                VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY_FAILED);
        virObjectEventStateQueue(driver->domainEventState, event);
    } else {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_POSTCOPY_FAILED);
    }
}


static int
qemuMigrationSrcWaitForSpice(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_SEAMLESS_MIGRATION) ||
        !priv->job.spiceMigration)
        return 0;

    VIR_DEBUG("Waiting for SPICE to finish migration");
    while (!priv->job.spiceMigrated && !priv->job.abortJob) {
        if (virDomainObjWait(vm) < 0)
            return -1;
    }
    return 0;
}


static void
qemuMigrationUpdateJobType(qemuDomainJobInfoPtr jobInfo)
{
    switch ((qemuMonitorMigrationStatus) jobInfo->stats.mig.status) {
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY:
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_POSTCOPY;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_NONE;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_FAILED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_CANCELED;
        break;

    // pre-switchover event from qemu migration before device serialization
    case QEMU_MONITOR_MIGRATION_STATUS_PRE_SWITCHOVER:
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_PAUSED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_DEVICE:
        // device serialization
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_MIGRATING;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_SETUP:
    case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLING:
    case QEMU_MONITOR_MIGRATION_STATUS_LAST:
        break;
    }
}


int
qemuMigrationAnyFetchStats(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           qemuDomainAsyncJob asyncJob,
                           qemuDomainJobInfoPtr jobInfo,
                           char **error)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMonitorMigrationStats stats;
    int rv;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    rv = qemuMonitorGetMigrationStats(priv->mon, &stats, error);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rv < 0)
        return -1;

    jobInfo->stats.mig = stats;

    return 0;
}


static const char *
qemuMigrationJobName(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    switch (priv->job.asyncActive) {
    case QEMU_ASYNC_JOB_MIGRATION_OUT:
        return _("migration out job");
    case QEMU_ASYNC_JOB_SAVE:
        return _("domain save job");
    case QEMU_ASYNC_JOB_DUMP:
        return _("domain core dump job");
    case QEMU_ASYNC_JOB_NONE:
        return _("undefined");
    case QEMU_ASYNC_JOB_MIGRATION_IN:
        return _("migration in job");
    case QEMU_ASYNC_JOB_SNAPSHOT:
        return _("snapshot job");
    case QEMU_ASYNC_JOB_START:
        return _("start job");
    case QEMU_ASYNC_JOB_LAST:
    default:
        return _("job");
    }
}


static int
qemuMigrationJobCheckStatus(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr jobInfo = priv->job.current;
    char *error = NULL;
    bool events = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT);
    int ret = -1;

    // if qemu not supports migration event report
    // libvirtd should query qemu to get the status with QMP command 'query-migrate'
    // otherwise mig.status is update on migration event handler
    if (!events ||
        jobInfo->stats.mig.status == QEMU_MONITOR_MIGRATION_STATUS_ERROR) {
        if (qemuMigrationAnyFetchStats(driver, vm, asyncJob, jobInfo, &error) < 0)
            return -1;
    }

    // update jobInfo->status based on jobInfo->stats.mig.status
    // from Migration status to Dom job status
    qemuMigrationUpdateJobType(jobInfo);

    switch (jobInfo->status) {
    case QEMU_DOMAIN_JOB_STATUS_NONE:
        virReportError(VIR_ERR_OPERATION_FAILED, _("%s: %s"),
                       qemuMigrationJobName(vm), _("is not active"));
        goto cleanup;

    case QEMU_DOMAIN_JOB_STATUS_FAILED:
        virReportError(VIR_ERR_OPERATION_FAILED, _("%s: %s"),
                       qemuMigrationJobName(vm),
                       error ? error : _("unexpectedly failed"));
        goto cleanup;

    case QEMU_DOMAIN_JOB_STATUS_CANCELED:
        virReportError(VIR_ERR_OPERATION_ABORTED, _("%s: %s"),
                       qemuMigrationJobName(vm), _("canceled by client"));
        goto cleanup;

    case QEMU_DOMAIN_JOB_STATUS_COMPLETED:
    case QEMU_DOMAIN_JOB_STATUS_ACTIVE:
    case QEMU_DOMAIN_JOB_STATUS_MIGRATING:
    case QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED:
    case QEMU_DOMAIN_JOB_STATUS_POSTCOPY:
    case QEMU_DOMAIN_JOB_STATUS_PAUSED:
        break;
    }

    ret = 0;

 cleanup:
    VIR_FREE(error);
    return ret;
}


enum qemuMigrationCompletedFlags {
    QEMU_MIGRATION_COMPLETED_ABORT_ON_ERROR = (1 << 0),
    /* This flag should only be set when run on src host */
    QEMU_MIGRATION_COMPLETED_CHECK_STORAGE  = (1 << 1),
    QEMU_MIGRATION_COMPLETED_POSTCOPY       = (1 << 2),
    QEMU_MIGRATION_COMPLETED_PRE_SWITCHOVER = (1 << 3),
};


/**
 * Returns 1 if migration completed successfully,
 *         0 if the domain is still being migrated,
 *         -1 migration failed,
 *         -2 something else failed, we need to cancel migration.
 */
static int
qemuMigrationAnyCompleted(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          qemuDomainAsyncJob asyncJob,
                          virConnectPtr dconn,
                          unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr jobInfo = priv->job.current;
    int pauseReason;

    // migration finished by check async job status which is set by event handler
    // when get migration event, event handler will update job.current->stats.mig.status
    if (qemuMigrationJobCheckStatus(driver, vm, asyncJob) < 0)
        goto error;

    /* This flag should only be set when run on src host */
    if (flags & QEMU_MIGRATION_COMPLETED_CHECK_STORAGE &&
        qemuMigrationSrcNBDStorageCopyReady(vm, asyncJob) < 0)
        goto error;

    /* This flag should only be set when run on src host */
    if (flags & QEMU_MIGRATION_COMPLETED_ABORT_ON_ERROR &&
        virDomainObjGetState(vm, &pauseReason) == VIR_DOMAIN_PAUSED &&
        pauseReason == VIR_DOMAIN_PAUSED_IOERROR) {
        virReportError(VIR_ERR_OPERATION_FAILED, _("%s: %s"),
                       qemuMigrationJobName(vm), _("failed due to I/O error"));
        goto error;
    }

    // only source check this
    if (dconn && virConnectIsAlive(dconn) <= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Lost connection to destination host"));
        goto error;
    }

    /* Migration was paused before serializing device state, let's return to
     * the caller so that it can finish all block jobs, resume migration, and
     * wait again for the real end of the migration.
     * source side
     */
    if (flags & QEMU_MIGRATION_COMPLETED_PRE_SWITCHOVER &&
        jobInfo->status == QEMU_DOMAIN_JOB_STATUS_PAUSED) {
        VIR_DEBUG("Migration paused before switchover");
        return 1;
    }

    /* In case of postcopy the source considers migration completed at the
     * moment it switched from active to postcopy-active state. The destination
     * will continue waiting until the migrate state changes to completed.
     */
    if (flags & QEMU_MIGRATION_COMPLETED_POSTCOPY &&
        jobInfo->status == QEMU_DOMAIN_JOB_STATUS_POSTCOPY) {
        VIR_DEBUG("Migration switched to post-copy");
        return 1;
    }

    if (jobInfo->status == QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED)
        return 1;
    else
        return 0;

 error:
    switch (jobInfo->status) {
    case QEMU_DOMAIN_JOB_STATUS_MIGRATING:
    case QEMU_DOMAIN_JOB_STATUS_POSTCOPY:
    case QEMU_DOMAIN_JOB_STATUS_PAUSED:
        /* The migration was aborted by us rather than QEMU itself. */
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_FAILED;
        return -2;

    case QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED:
        /* Something failed after QEMU already finished the migration. */
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_FAILED;
        return -1;

    case QEMU_DOMAIN_JOB_STATUS_FAILED:
    case QEMU_DOMAIN_JOB_STATUS_CANCELED:
        /* QEMU aborted the migration. */
        return -1;

    case QEMU_DOMAIN_JOB_STATUS_ACTIVE:
    case QEMU_DOMAIN_JOB_STATUS_COMPLETED:
    case QEMU_DOMAIN_JOB_STATUS_NONE:
        /* Impossible. */
        break;
    }

    return -1;
}


/* Returns 0 on success, -2 when migration needs to be cancelled, or -1 when
 * QEMU reports failed migration.
 */
static int
qemuMigrationSrcWaitForCompletion(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  qemuDomainAsyncJob asyncJob,
                                  virConnectPtr dconn,
                                  unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr jobInfo = priv->job.current;
    bool events = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT);
    int rv;

    jobInfo->status = QEMU_DOMAIN_JOB_STATUS_MIGRATING;

    while ((rv = qemuMigrationAnyCompleted(driver, vm, asyncJob,
                                           dconn, flags)) != 1) {
        // when error, return directly
        if (rv < 0)
            return rv;

        if (events) {
            // for each migration event, I'm waken up, then check status
            if (virDomainObjWait(vm) < 0) {
                jobInfo->status = QEMU_DOMAIN_JOB_STATUS_FAILED;
                return -2;
            }
        } else {
            // NOTE: if qemu does not support migration event notification to libvirt
            /* Poll every 50ms for progress & to allow cancellation */
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000ull };

            virObjectUnlock(vm);
            nanosleep(&ts, NULL);
            virObjectLock(vm);
        }
    }


    // goes here means we got completed or post-copy event from QEME

    if (events)
        // update migration stats when got completed event from QEMU
        // by sending query-migrate QMP command to QEMU
        ignore_value(qemuMigrationAnyFetchStats(driver, vm, asyncJob, jobInfo, NULL));

    qemuDomainJobInfoUpdateTime(jobInfo);
    qemuDomainJobInfoUpdateDowntime(jobInfo);

    // free previous completed job
    // allocate a new completed job for each migration process when migration completed
    VIR_FREE(priv->job.completed);
    if (VIR_ALLOC(priv->job.completed) == 0) {
        // copied jobinfo from current
        *priv->job.completed = *jobInfo;
        // stats job
        priv->job.completed->status = QEMU_DOMAIN_JOB_STATUS_COMPLETED;
    }

    if (asyncJob != QEMU_ASYNC_JOB_MIGRATION_OUT &&
        // migration status
        // QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED vs QEMU_DOMAIN_JOB_STATUS_COMPLETED
        // QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED: qemu reported done but
        // we still operation at libvirtd side for a completed state
        jobInfo->status == QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED)
        jobInfo->status = QEMU_DOMAIN_JOB_STATUS_COMPLETED;

    return 0;
}


static int
qemuMigrationDstWaitForCompletion(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  qemuDomainAsyncJob asyncJob,
                                  bool postcopy)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned int flags = 0;
    int rv;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT))
        return 0;

    VIR_DEBUG("Waiting for incoming migration to complete");

    if (postcopy)
        flags = QEMU_MIGRATION_COMPLETED_POSTCOPY;

    // completed when status in post-copy or completed!!!
    while ((rv = qemuMigrationAnyCompleted(driver, vm, asyncJob,
                                           NULL, flags)) != 1) {
        // block vm condition and free vm lock
        if (rv < 0 || virDomainObjWait(vm) < 0)
            return -1;
    }

    return 0;
}


static int
qemuMigrationSrcGraphicsRelocate(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 qemuMigrationCookiePtr cookie,
                                 const char *graphicsuri)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    const char *listenAddress = NULL;
    virSocketAddr addr;
    virURIPtr uri = NULL;
    int type = -1;
    int port = -1;
    int tlsPort = -1;
    const char *tlsSubject = NULL;

    if (!cookie || (!cookie->graphics && !graphicsuri))
        return 0;

    if (graphicsuri && !(uri = virURIParse(graphicsuri)))
        goto cleanup;

    if (cookie->graphics) {
        type = cookie->graphics->type;

        listenAddress = cookie->graphics->listen;

        if (!listenAddress ||
            (virSocketAddrParse(&addr, listenAddress, AF_UNSPEC) > 0 &&
             virSocketAddrIsWildcard(&addr)))
            listenAddress = cookie->remoteHostname;

        port = cookie->graphics->port;
        tlsPort = cookie->graphics->tlsPort;
        tlsSubject = cookie->graphics->tlsSubject;
    }

    if (uri) {
        size_t i;

        if ((type = virDomainGraphicsTypeFromString(uri->scheme)) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unknown graphics type %s"), uri->scheme);
            goto cleanup;
        }

        if (uri->server)
            listenAddress = uri->server;
        if (uri->port > 0)
            port = uri->port;

        for (i = 0; i < uri->paramsCount; i++) {
            virURIParamPtr param = uri->params + i;

            if (STRCASEEQ(param->name, "tlsPort")) {
                if (virStrToLong_i(param->value, NULL, 10, &tlsPort) < 0) {
                    virReportError(VIR_ERR_INVALID_ARG,
                                   _("invalid tlsPort number: %s"),
                                   param->value);
                    goto cleanup;
                }
            } else if (STRCASEEQ(param->name, "tlsSubject")) {
                tlsSubject = param->value;
            }
        }
    }

    /* QEMU doesn't support VNC relocation yet, so
     * skip it to avoid generating an error
     */
    if (type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
        ret = 0;
        goto cleanup;
    }

    /* Older libvirt sends port == 0 for listen type='none' graphics. It's
     * safe to ignore such requests since relocation to unknown port does
     * not make sense in general.
     */
    if (port <= 0 && tlsPort <= 0) {
        ret = 0;
        goto cleanup;
    }

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT) == 0) {
        ret = qemuMonitorGraphicsRelocate(priv->mon, type, listenAddress,
                                          port, tlsPort, tlsSubject);
        priv->job.spiceMigration = !ret;
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            ret = -1;
    }

 cleanup:
    virURIFree(uri);
    return ret;
}


static int
qemuMigrationDstOPDRelocate(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                            virDomainObjPtr vm,
                            qemuMigrationCookiePtr cookie)
{
    virDomainNetDefPtr netptr;
    int ret = -1;
    size_t i;

    for (i = 0; i < cookie->network->nnets; i++) {
        netptr = vm->def->nets[i];

        switch (cookie->network->net[i].vporttype) {
        case VIR_NETDEV_VPORT_PROFILE_NONE:
        case VIR_NETDEV_VPORT_PROFILE_8021QBG:
        case VIR_NETDEV_VPORT_PROFILE_8021QBH:
           break;
        case VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH:
            if (virNetDevOpenvswitchSetMigrateData(cookie->network->net[i].portdata,
                                                   netptr->ifname) != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to run command to set OVS port data for "
                                 "interface %s"), netptr->ifname);
                goto cleanup;
            }
            break;
        default:
            break;
        }
    }

    ret = 0;
 cleanup:
    return ret;
}


int
qemuMigrationDstCheckProtocol(virQEMUCapsPtr qemuCaps,
                              const char *migrateFrom)
{
    if (STRPREFIX(migrateFrom, "rdma")) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MIGRATE_RDMA)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("incoming RDMA migration is not supported "
                             "with this QEMU binary"));
            return -1;
        }
    } else if (!STRPREFIX(migrateFrom, "tcp") &&
               !STRPREFIX(migrateFrom, "exec") &&
               !STRPREFIX(migrateFrom, "fd") &&
               !STRPREFIX(migrateFrom, "unix") &&
               STRNEQ(migrateFrom, "stdio")) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("unknown migration protocol"));
        return -1;
    }

    return 0;
}


char *
qemuMigrationDstGetURI(const char *migrateFrom,
                       int migrateFd)
{
    char *uri = NULL;

    if (STREQ(migrateFrom, "stdio"))
        ignore_value(virAsprintf(&uri, "fd:%d", migrateFd));
    else
        ignore_value(VIR_STRDUP(uri, migrateFrom));

    return uri;
}


// for peer to peer(tunneled, native), dst libvirtd does not run this
// this runs only for direct migration!!!
int
qemuMigrationDstRun(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    const char *uri,
                    qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int rv;

    VIR_DEBUG("Setting up incoming migration with URI %s", uri);

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    // set migration uri by QMP command not from command line
    rv = qemuMonitorMigrateIncoming(priv->mon, uri);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rv < 0)
        goto cleanup;

    if (asyncJob == QEMU_ASYNC_JOB_MIGRATION_IN) {
        /* qemuMigrationDstWaitForCompletion is called from the Finish phase */
        ret = 0;
        goto cleanup;
    }

    if (qemuMigrationDstWaitForCompletion(driver, vm, asyncJob, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


/* This is called for outgoing non-p2p migrations when a connection to the
 * client which initiated the migration was closed but we were waiting for it
 * to follow up with the next phase, that is, in between
 * qemuDomainMigrateBegin3 and qemuDomainMigratePerform3 or
 * qemuDomainMigratePerform3 and qemuDomainMigrateConfirm3.
 */
static void
qemuMigrationSrcCleanup(virDomainObjPtr vm,
                        virConnectPtr conn,
                        void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    VIR_DEBUG("vm=%s, conn=%p, asyncJob=%s, phase=%s",
              vm->def->name, conn,
              qemuDomainAsyncJobTypeToString(priv->job.asyncActive),
              qemuDomainAsyncJobPhaseToString(priv->job.asyncActive,
                                              priv->job.phase));

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_OUT))
        return;

    VIR_DEBUG("The connection which started outgoing migration of domain %s"
              " was closed; canceling the migration",
              vm->def->name);

    switch ((qemuMigrationJobPhase) priv->job.phase) {
    case QEMU_MIGRATION_PHASE_BEGIN3:
        /* just forget we were about to migrate */
        qemuDomainObjDiscardAsyncJob(driver, vm);
        break;

    case QEMU_MIGRATION_PHASE_PERFORM3_DONE:
        VIR_WARN("Migration of domain %s finished but we don't know if the"
                 " domain was successfully started on destination or not",
                 vm->def->name);
        qemuMigrationParamsReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                 priv->job.migParams, priv->job.apiFlags);
        /* clear the job and let higher levels decide what to do */
        qemuDomainObjDiscardAsyncJob(driver, vm);
        break;

    case QEMU_MIGRATION_PHASE_PERFORM3:
        /* cannot be seen without an active migration API; unreachable */
    case QEMU_MIGRATION_PHASE_CONFIRM3:
    case QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED:
        /* all done; unreachable */
    case QEMU_MIGRATION_PHASE_PREPARE:
    case QEMU_MIGRATION_PHASE_FINISH2:
    case QEMU_MIGRATION_PHASE_FINISH3:
        /* incoming migration; unreachable */
    case QEMU_MIGRATION_PHASE_PERFORM2:
        /* single phase outgoing migration; unreachable */
    case QEMU_MIGRATION_PHASE_NONE:
    case QEMU_MIGRATION_PHASE_LAST:
        /* unreachable */
        ;
    }
}


/* The caller is supposed to lock the vm and start a migration job. */
static char *
qemuMigrationSrcBeginPhase(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           const char *xmlin,
                           const char *dname,
                           char **cookieout,
                           int *cookieoutlen,
                           size_t nmigrate_disks,
                           const char **migrate_disks,
                           unsigned long flags)
{
    char *rv = NULL;
    qemuMigrationCookiePtr mig = NULL;
    virDomainDefPtr def = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCapsPtr caps = NULL;
    unsigned int cookieFlags = QEMU_MIGRATION_COOKIE_LOCKSTATE;

    VIR_DEBUG("driver=%p, vm=%p, xmlin=%s, dname=%s,"
              " cookieout=%p, cookieoutlen=%p,"
              " nmigrate_disks=%zu, migrate_disks=%p, flags=0x%lx",
              driver, vm, NULLSTR(xmlin), NULLSTR(dname),
              cookieout, cookieoutlen, nmigrate_disks,
              migrate_disks, flags);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    /* Only set the phase if we are inside QEMU_ASYNC_JOB_MIGRATION_OUT.
     * Otherwise we will start the async job later in the perform phase losing
     * change protection.
     */
    if (priv->job.asyncActive == QEMU_ASYNC_JOB_MIGRATION_OUT)
        // change migration phase to BEGIN3 for v3 migration(which set asyncActive == QEMU_ASYNC_JOB_MIGRATION_OUT)
        qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_BEGIN3);

    // for p2p case, we should check it before, but for non-p2p which calls qemuMigrationSrcBeginPhase as well but not check it before
    if (!qemuMigrationSrcIsAllowed(driver, vm, true, flags))
        goto cleanup;

    // for p2p case, we should check it before, but for non-p2p which calls qemuMigrationSrcBeginPhase as well but not check it before
    if (!(flags & (VIR_MIGRATE_UNSAFE | VIR_MIGRATE_OFFLINE)) &&
        !qemuMigrationSrcIsSafe(vm->def, nmigrate_disks, migrate_disks, flags))
        goto cleanup;

    if (flags & VIR_MIGRATE_POSTCOPY &&
        (!(flags & VIR_MIGRATE_LIVE) ||
         flags & VIR_MIGRATE_PAUSED)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy migration is not supported with non-live "
                         "or paused migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_POSTCOPY && flags & VIR_MIGRATE_TUNNELLED) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy is not supported with tunnelled migration"));
        goto cleanup;
    }

    // has non shared disk flag set with 'virsh migrate --copy-storage-all'
    if (flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC)) {
        bool has_drive_mirror =  virQEMUCapsGet(priv->qemuCaps,
                                                QEMU_CAPS_DRIVE_MIRROR);

        if (nmigrate_disks) {
            // user set which disk we should migrate to remote
            if (has_drive_mirror) {
                // driver must support drive-mirror command!!!
                // otherwise migrate lock disk is not supported.
                size_t i, j;
                /* Check user requested only known disk targets. */
                for (i = 0; i < nmigrate_disks; i++) {
                    for (j = 0; j < vm->def->ndisks; j++) {
                        if (STREQ(vm->def->disks[j]->dst, migrate_disks[i]))
                            break;
                    }

                    if (j == vm->def->ndisks) {
                        virReportError(VIR_ERR_INVALID_ARG,
                                       _("disk target %s not found"),
                                       migrate_disks[i]);
                        goto cleanup;
                    }
                }

                if (flags & VIR_MIGRATE_TUNNELLED) {
                    virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                                   _("Selecting disks to migrate is not "
                                     "implemented for tunnelled migration"));
                    goto cleanup;
                }
            } else {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("qemu does not support drive-mirror command"));
                goto cleanup;
            }
        }

        if (has_drive_mirror) {
            /* TODO support NBD for TUNNELLED migration */
            if (flags & VIR_MIGRATE_TUNNELLED) {
                VIR_WARN("NBD in tunnelled migration is currently not supported");
            } else {
                cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
                priv->nbdPort = 0;
            }
        }
    }

    // Define the domain as persistent on the destination host after successful migration
    if (virDomainDefHasMemoryHotplug(vm->def) ||
        ((flags & VIR_MIGRATE_PERSIST_DEST) &&
         vm->newDef && virDomainDefHasMemoryHotplug(vm->newDef)))
        cookieFlags |= QEMU_MIGRATION_COOKIE_MEMORY_HOTPLUG;

    if (!qemuDomainVcpuHotplugIsInOrder(vm->def) ||
        ((flags & VIR_MIGRATE_PERSIST_DEST) &&
         vm->newDef && !qemuDomainVcpuHotplugIsInOrder(vm->newDef)))
        //TODO: cookieFlags used for what???
        cookieFlags |= QEMU_MIGRATION_COOKIE_CPU_HOTPLUG;

    if (priv->origCPU)
        cookieFlags |= QEMU_MIGRATION_COOKIE_CPU;

    cookieFlags |= QEMU_MIGRATION_COOKIE_ALLOW_REBOOT;

    if (!(flags & VIR_MIGRATE_OFFLINE))
        cookieFlags |= QEMU_MIGRATION_COOKIE_CAPS;

    // create cookie at source based on driver and vm info
    if (!(mig = qemuMigrationEatCookie(driver, vm, NULL, 0, 0)))
        goto cleanup;

    // generate cookie at source that includes several information saved at cookieout
    /*
     * </qemu-migration>
     *   <name>vm100</name>
     *   <uuid>e8b6545e-3fef-4a98-b222-18b2eed9f2f1</uuid>
     *   <hostname>dev</hostname>
     *   <hostuuid>e6bf2fb1-e252-48cc-8ee4-d79167a986ce</hostuuid>
     *   <feature name='lockstate'/>
     *   <feature name='memory-hotplug'/>
     *   <nbd>
     *     <disk target='vda' capacity='8589934592'/>
     *     <disk target='vdc' capacity='358400'/>
     *   </nbd>
     *   <allowReboot value='yes'/>
     *   <capabilities>
     *     <cap name='xbzrle' auto='no'/>
     *     <cap name='auto-converge' auto='no'/>
     *     <cap name='rdma-pin-all' auto='no'/>
     *     <cap name='postcopy-ram' auto='no'/>
     *     <cap name='compress' auto='no'/>
     *     <cap name='pause-before-switchover' auto='yes'/>
     *     <cap name='late-block-activate' auto='no'/>
     *   </capabilities>
     * </qemu-migration>
     */
    if (qemuMigrationBakeCookie(mig, driver, vm,
                                QEMU_MIGRATION_SOURCE,
                                cookieout, cookieoutlen,
                                cookieFlags) < 0)
        goto cleanup;

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (flags & (VIR_MIGRATE_NON_SHARED_DISK |
                     VIR_MIGRATE_NON_SHARED_INC)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration cannot handle "
                             "non-shared storage"));
            goto cleanup;
        }
        if (!(flags & VIR_MIGRATE_PERSIST_DEST)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration must be specified with "
                             "the persistent flag set"));
            goto cleanup;
        }
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("tunnelled offline migration does not "
                             "make sense"));
            goto cleanup;
        }
    }

    if (xmlin) {
        // if user passed new xml use it
        // otherwise dump it from memory which is used for this vm
        if (!(def = virDomainDefParseString(xmlin, caps, driver->xmlopt, priv->qemuCaps,
                                            VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                            VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
            goto cleanup;

        if (!qemuDomainCheckABIStability(driver, vm, def))
            goto cleanup;

        rv = qemuDomainDefFormatLive(driver, def, NULL, false, true);
    } else {
        rv = qemuDomainDefFormatLive(driver, vm->def, priv->origCPU,
                                     false, true);
    }

 cleanup:
    qemuMigrationCookieFree(mig);
    virObjectUnref(caps);
    virDomainDefFree(def);
    return rv;
}

char *
qemuMigrationSrcBegin(virConnectPtr conn,
                      virDomainObjPtr vm,
                      const char *xmlin,
                      const char *dname,
                      char **cookieout,
                      int *cookieoutlen,
                      size_t nmigrate_disks,
                      const char **migrate_disks,
                      unsigned long flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    char *xml = NULL;
    qemuDomainAsyncJob asyncJob;

    if ((flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                  flags) < 0)
            goto cleanup;
        asyncJob = QEMU_ASYNC_JOB_MIGRATION_OUT;
    } else {
        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
            goto cleanup;
        asyncJob = QEMU_ASYNC_JOB_NONE;
    }

    qemuMigrationSrcStoreDomainState(vm);

    if (!(flags & VIR_MIGRATE_OFFLINE) && virDomainObjCheckActive(vm) < 0)
        goto endjob;

    /* Check if there is any ejected media.
     * We don't want to require them on the destination.
     */
    if (!(flags & VIR_MIGRATE_OFFLINE) &&
        qemuProcessRefreshDisks(driver, vm, asyncJob) < 0)
        goto endjob;

    if (!(xml = qemuMigrationSrcBeginPhase(driver, vm, xmlin, dname,
                                           cookieout, cookieoutlen,
                                           nmigrate_disks, migrate_disks, flags)))
        goto endjob;

    if ((flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        /* We keep the job active across API calls until the confirm() call.
         * This prevents any other APIs being invoked while migration is taking
         * place.
         */
        if (virCloseCallbacksSet(driver->closeCallbacks, vm, conn,
                                 qemuMigrationSrcCleanup) < 0) {
            VIR_FREE(xml);
            goto endjob;
        }
        qemuMigrationJobContinue(vm);
    } else {
        goto endjob;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return xml;

 endjob:
    if (flags & VIR_MIGRATE_CHANGE_PROTECTION)
        qemuMigrationJobFinish(driver, vm);
    else
        qemuDomainObjEndJob(driver, vm);
    goto cleanup;
}


/* Prepare is the first step, and it runs on the destination host.
 */

static void
qemuMigrationDstPrepareCleanup(virQEMUDriverPtr driver,
                               virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    VIR_DEBUG("driver=%p, vm=%s, job=%s, asyncJob=%s",
              driver,
              vm->def->name,
              qemuDomainJobTypeToString(priv->job.active),
              qemuDomainAsyncJobTypeToString(priv->job.asyncActive));

    virPortAllocatorRelease(priv->migrationPort);
    priv->migrationPort = 0;

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_IN))
        return;
    qemuDomainObjDiscardAsyncJob(driver, vm);
}

static qemuProcessIncomingDefPtr
qemuMigrationDstPrepare(virDomainObjPtr vm,
                        bool tunnel,
                        const char *protocol,
                        const char *listenAddress,
                        unsigned short port,
                        int fd)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuProcessIncomingDefPtr inc = NULL;
    char *migrateFrom = NULL;

    if (tunnel) {
        if (VIR_STRDUP(migrateFrom, "stdio") < 0)
            goto cleanup;
    } else {
        bool encloseAddress = false;
        bool hostIPv6Capable = false;
        struct addrinfo *info = NULL;
        struct addrinfo hints = { .ai_flags = AI_ADDRCONFIG,
                                  .ai_socktype = SOCK_STREAM };
        const char *incFormat;

        if (getaddrinfo("::", NULL, &hints, &info) == 0) {
            freeaddrinfo(info);
            hostIPv6Capable = true;
        }

        if (listenAddress) {
            if (virSocketAddrNumericFamily(listenAddress) == AF_INET6) {
                if (!hostIPv6Capable) {
                    virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                                   _("host isn't capable of IPv6"));
                    goto cleanup;
                }
                /* IPv6 address must be escaped in brackets on the cmd line */
                encloseAddress = true;
            } else {
                /* listenAddress is a hostname or IPv4 */
            }
        } else if (hostIPv6Capable) {
            /* Listen on :: instead of 0.0.0.0 if QEMU understands it
             * and there is at least one IPv6 address configured
             */
            listenAddress = "::";
            encloseAddress = true;
        } else {
            listenAddress = "0.0.0.0";
        }

        /* QEMU will be started with from command line
         *   -incoming protocol:[<IPv6 addr>]:port,
         *   -incoming protocol:<IPv4 addr>:port, or
         *   -incoming protocol:<hostname>:port
         *
         *   -incoming tcp:[host]:port[,to=maxport][,ipv4=on|off][,ipv6=on|off]
         *   -incoming rdma:host:port[,ipv4=on|off][,ipv6=on|off]
         *   Prepare for incoming migration, listen on a given tcp port.
         *
         *   -incoming defer
         *   Wait for the URI to be specified via migrate_incoming QMP command
         */
        if (encloseAddress)
            incFormat = "%s:[%s]:%d";
        else
            incFormat = "%s:%s:%d";
        // listenAddress set by source, let dst to bind this address for migration
        if (virAsprintf(&migrateFrom, incFormat,
                        protocol, listenAddress, port) < 0)
            goto cleanup;
    }

    // listenAddress(from source or 0.0.0.0 default) is used for:
    // migration uri: tcp:listenAddress:port
    // nbd server started by qemu as well for non-shared disk migration
    inc = qemuProcessIncomingDefNew(priv->qemuCaps, listenAddress,
                                    migrateFrom, fd, NULL);

 cleanup:
    VIR_FREE(migrateFrom);
    return inc;
}

static int
qemuMigrationDstPrepareAny(virQEMUDriverPtr driver,
                           virConnectPtr dconn,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           virDomainDefPtr *def,
                           const char *origname,
                           virStreamPtr st,
                           const char *protocol,
                           unsigned short port,
                           bool autoPort,
                           const char *listenAddress,
                           size_t nmigrate_disks,
                           const char **migrate_disks,
                           int nbdPort,
                           qemuMigrationParamsPtr migParams,
                           unsigned long flags)
{
    virDomainObjPtr vm = NULL;
    virObjectEventPtr event = NULL;
    int ret = -1;
    int dataFD[2] = { -1, -1 };
    qemuDomainObjPrivatePtr priv = NULL;
    qemuMigrationCookiePtr mig = NULL;
    bool tunnel = !!st;
    char *xmlout = NULL;
    unsigned int cookieFlags;
    unsigned int startFlags;
    virCapsPtr caps = NULL;
    qemuProcessIncomingDefPtr incoming = NULL;
    bool taint_hook = false;
    bool stopProcess = false;
    bool relabel = false;
    int rv;
    char *tlsAlias = NULL;

    virNWFilterReadLockFilterUpdates();

    // flags sent by source with user flags and extra flags added by source libvirtd
    if (flags & VIR_MIGRATE_OFFLINE) {
        if (flags & (VIR_MIGRATE_NON_SHARED_DISK |
                     VIR_MIGRATE_NON_SHARED_INC)) {
            // offline can not migrate local storage!!!
            // local storage
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration cannot handle "
                             "non-shared storage"));
            goto cleanup;
        }
        // otherwise as it's offline, if no persistent, vm is gone after migration at dst side if libvirtd restart at dst
        if (!(flags & VIR_MIGRATE_PERSIST_DEST)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration must be specified with "
                             "the persistent flag set"));
            goto cleanup;
        }
        if (tunnel) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("tunnelled offline migration does not "
                             "make sense"));
            goto cleanup;
        }
        cookieFlags = 0;
    } else {
        cookieFlags = QEMU_MIGRATION_COOKIE_GRAPHICS |
                      QEMU_MIGRATION_COOKIE_CAPS;
    }

    if (flags & VIR_MIGRATE_POSTCOPY &&
        (!(flags & VIR_MIGRATE_LIVE) ||
         flags & VIR_MIGRATE_PAUSED)) {
        // post-copy is not valid ofr non-live, or vm is paused when migration happens.
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy migration is not supported with non-live "
                         "or paused migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_POSTCOPY && flags & VIR_MIGRATE_TUNNELLED) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy is not supported with tunnelled migration"));
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!qemuMigrationSrcIsAllowedHostdev(*def))
        goto cleanup;

    /* Let migration hook filter domain XML
     * hook at: /etc/libvirt/hooks/qemu
     * */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml;
        int hookret;

        if (!(xml = qemuDomainDefFormatXML(driver, *def,
                                           VIR_DOMAIN_XML_SECURE |
                                           VIR_DOMAIN_XML_MIGRATABLE)))
            goto cleanup;

        // run migration hook from disk if present, pass xml to that hook as stdin
        /* with domain XML sent to standard input of the script.
         * In this case, the script acts as a filter and
         * is supposed to modify the domain XML and
         * print it out on its standard output.
         * Empty output is identical to copying the input XML without changing it.
         * In case the script returns failure or the output XML is not valid,
         * incoming migration will be canceled.
         * This hook may be used, e.g.,
         * to change location of disk images for incoming domains.
         */
        hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, (*def)->name,
                              VIR_HOOK_QEMU_OP_MIGRATE, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, &xmlout);
        VIR_FREE(xml);

        if (hookret < 0) {
            goto cleanup;
        } else if (hookret == 0) {
            if (virStringIsEmpty(xmlout)) {
                VIR_DEBUG("Migrate hook filter returned nothing; using the"
                          " original XML");
            } else {
                virDomainDefPtr newdef;

                // use the filtered xml if return by qemu hook
                VIR_DEBUG("Using hook-filtered domain XML: %s", xmlout);
                newdef = virDomainDefParseString(xmlout, caps, driver->xmlopt, NULL,
                                                 VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                                 VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE);
                if (!newdef)
                    goto cleanup;

                if (!qemuDomainDefCheckABIStability(driver, *def, newdef)) {
                    virDomainDefFree(newdef);
                    goto cleanup;
                }

                virDomainDefFree(*def);
                // use the new xml
                *def = newdef;
                /* We should taint the domain here. However, @vm and therefore
                 * privateData too are still NULL, so just notice the fact and
                 * taint it later. */
                taint_hook = true;
            }
        }
    }

    // add a new vm so that user can see this vm later on
    if (!(vm = virDomainObjListAdd(driver->domains, *def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    *def = NULL;

    priv = vm->privateData;
    if (VIR_STRDUP(priv->origname, origname) < 0)
        goto cleanup;

    if (taint_hook) {
        /* Domain XML has been altered by a hook script.
         * if hook runs without modify the xml, hookRun is false!!!
         */
        priv->hookRun = true;
    }

    // eat cookie sent by source libvirtd to qemuMigrationCookiePtr
    // later on we use this cookie
    if (!(mig = qemuMigrationEatCookie(driver, vm, cookiein, cookieinlen,
                                       QEMU_MIGRATION_COOKIE_LOCKSTATE |
                                       QEMU_MIGRATION_COOKIE_NBD |
                                       QEMU_MIGRATION_COOKIE_MEMORY_HOTPLUG |
                                       QEMU_MIGRATION_COOKIE_CPU_HOTPLUG |
                                       QEMU_MIGRATION_COOKIE_CPU |
                                       QEMU_MIGRATION_COOKIE_ALLOW_REBOOT |
                                       QEMU_MIGRATION_COOKIE_CAPS)))
        goto cleanup;

    if (STREQ_NULLABLE(protocol, "rdma") &&
        !virMemoryLimitIsSet(vm->def->mem.hard_limit)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot start RDMA migration with no memory hard "
                         "limit set"));
        goto cleanup;
    }

    // create empty storage file as source will migrate local disk to me
    if (qemuMigrationDstPrecreateStorage(vm, mig->nbd,
                                         nmigrate_disks, migrate_disks,
                                         !!(flags & VIR_MIGRATE_NON_SHARED_INC)) < 0)
        goto cleanup;

    // dst starts migration async job with mask NONE(so that no other job is allowed to run even abort, query, destroy)
    if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                              flags) < 0)
        goto cleanup;
    // set phaset to prepare at dst host
    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PREPARE);

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    if (flags & VIR_MIGRATE_OFFLINE)
        goto done;

    // for tunnel, we create a pipe
    // write side is libvirtd connection with source
    // read side passed(fd passed) to qemu for reading
    if (tunnel &&
        (pipe(dataFD) < 0 || virSetCloseExec(dataFD[1]) < 0)) {
        virReportSystemError(errno, "%s",
                             _("cannot create pipe for tunnelled migration"));
        goto stopjob;
    }

    startFlags = VIR_QEMU_PROCESS_START_AUTODESTROY;

    // now we plan to start qemu process without image as it's paused after starts
    if (qemuProcessInit(driver, vm, mig->cpu, QEMU_ASYNC_JOB_MIGRATION_IN,
                        true, startFlags) < 0)
        goto stopjob;
    stopProcess = true;

    // use cookie infor for new create vm
    priv->allowReboot = mig->allowReboot;

    // port is from migrationuri from source or auto generated by dst
    // protocol from migrationuri or default 'tcp'
    if (!(incoming = qemuMigrationDstPrepare(vm, tunnel, protocol,
                                             listenAddress, port,
                                             dataFD[0])))
        goto stopjob;

    if (qemuProcessPrepareDomain(driver, vm, startFlags) < 0)
        goto stopjob;

    if (qemuProcessPrepareHost(driver, vm, startFlags) < 0)
        goto stopjob;

    // for live migration, start qemu-process but with cpu paused
    // as no image passed now, if runs, that will cause error!!!
    rv = qemuProcessLaunch(dconn, driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                           incoming, NULL,
                           VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START,
                           startFlags);
    if (rv < 0) {
        if (rv == -2)
            relabel = true;
        goto stopjob;
    }
    relabel = true;

    if (tunnel) {
        // write side points to stream connection which is libvirtd connection
        if (virFDStreamOpen(st, dataFD[1]) < 0) {
            virReportSystemError(errno, "%s",
                                 _("cannot pass pipe for tunnelled migration"));
            goto stopjob;
        }
        dataFD[1] = -1; /* 'st' owns the FD now & will close it */
    }

    if (STREQ_NULLABLE(protocol, "rdma") &&
        virProcessSetMaxMemLock(vm->pid, vm->def->mem.hard_limit << 10) < 0) {
        goto stopjob;
    }

    // check parameter if supported by vm(dst) here
    if (qemuMigrationParamsCheck(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                                 migParams, mig->caps->automatic) < 0)
        goto stopjob;

    /* Migrations using TLS need to add the "tls-creds-x509" object and
     * set the migration TLS parameters */
    if (flags & VIR_MIGRATE_TLS) {
        if (qemuMigrationParamsEnableTLS(driver, vm, true,
                                         QEMU_ASYNC_JOB_MIGRATION_IN,
                                         &tlsAlias, NULL,
                                         migParams) < 0)
            goto stopjob;
    } else {
        if (qemuMigrationParamsDisableTLS(vm, migParams) < 0)
            goto stopjob;
    }

    // set migration parameter at dst by QMP command!!!
    // NOTE: we already save the orignal migration parameter at priv->job->migParams
    if (qemuMigrationParamsApply(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                                 migParams) < 0)
        goto stopjob;

    if (mig->nbd &&
        flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NBD_SERVER)) {
        // dst qemu support nbd server caps for non-shared storage migration
        const char *nbdTLSAlias = NULL;

        if (flags & VIR_MIGRATE_TLS) {
            if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NBD_TLS)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("QEMU NBD server does not support TLS transport"));
                goto stopjob;
            }

            nbdTLSAlias = tlsAlias;
        }

        // start nbd server if non-shared storage is required and dst qemu supports nbd server cap
        // nbdPort can be set by user from source or 0 if not set
        if (qemuMigrationDstStartNBDServer(driver, vm, incoming->address,
                                           nmigrate_disks, migrate_disks,
                                           nbdPort, nbdTLSAlias) < 0) {
            goto stopjob;
        }
        cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    }

    if (mig->lockState) {
        VIR_DEBUG("Received lockstate %s", mig->lockState);
        VIR_FREE(priv->lockState);
        priv->lockState = mig->lockState;
        mig->lockState = NULL;
    } else {
        VIR_DEBUG("Received no lockstate");
    }

    // set migration uri here by qmp: migrate-incoming this is mostly used for direct migration
    // as we did not set migration uri from command line option.
    if (incoming->deferredURI &&
        qemuMigrationDstRun(driver, vm, incoming->deferredURI,
                            QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        goto stopjob;

    // for migration, startcpu is false, so it's paused
    if (qemuProcessFinishStartup(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                                 false, VIR_DOMAIN_PAUSED_MIGRATION) < 0)
        goto stopjob;

 done:
    // bake cookie and send it back to source for eating
    // the cookie has information that dst using for migration
    if (qemuMigrationBakeCookie(mig, driver, vm,
                                QEMU_MIGRATION_DESTINATION,
                                cookieout, cookieoutlen, cookieFlags) < 0) {
        /* We could tear down the whole guest here, but
         * cookie data is (so far) non-critical, so that
         * seems a little harsh. We'll just warn for now.
         */
        VIR_WARN("Unable to encode migration cookie");
    }

    // cleanup when vm is freed
    if (qemuDomainCleanupAdd(vm, qemuMigrationDstPrepareCleanup) < 0)
        goto stopjob;

    if (!(flags & VIR_MIGRATE_OFFLINE)) {
        // if it's offline migration, it's done here at dst side
        virDomainAuditStart(vm, "migrated", true);
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    }

    /* We keep the job active across API calls until the finish() call.
     * This prevents any other APIs being invoked while incoming
     * migration is taking place.
     *
     * here we release the owner of async migration job
     * so that any thread that runs migration rpc can continue the migration process
     * without warning!!!
     *
     * in source side migration runs in a single thread
     * but in dst side migration job(rpc call) may run in different threads!!!
     */
    qemuMigrationJobContinue(vm);

    if (autoPort)
        // save the migratin port if auto generated
        priv->migrationPort = port;

    /* in this case port is not auto selected and we don't need to manage it
     * anymore after cookie is baked
     */
    if (nbdPort != 0)
        priv->nbdPort = 0;
    ret = 0;

 cleanup:
    VIR_FREE(tlsAlias);
    qemuProcessIncomingDefFree(incoming);
    VIR_FREE(xmlout);
    VIR_FORCE_CLOSE(dataFD[0]);
    VIR_FORCE_CLOSE(dataFD[1]);
    if (ret < 0 && priv) {
        /* priv is set right after vm is added to the list of domains
         * and there is no 'goto cleanup;' in the middle of those */
        VIR_FREE(priv->origname);
        /* release if port is auto selected which is not the case if
         * it is given in parameters
         */
        if (nbdPort == 0)
            virPortAllocatorRelease(priv->nbdPort);
        priv->nbdPort = 0;
        virDomainObjRemoveTransientDef(vm);
        qemuDomainRemoveInactiveJob(driver, vm);
    }
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    qemuMigrationCookieFree(mig);
    virObjectUnref(caps);
    virNWFilterUnlockFilterUpdates();
    return ret;

 stopjob:
    // stop job when failure happens during migration prepare
    // reset migration paraemter set this time(send QMP command)
    qemuMigrationParamsReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                             priv->job.migParams, priv->job.apiFlags);

    if (stopProcess) {
        // kill vm in some cases
        unsigned int stopFlags = VIR_QEMU_PROCESS_STOP_MIGRATED;
        if (!relabel)
            stopFlags |= VIR_QEMU_PROCESS_STOP_NO_RELABEL;
        virDomainAuditStart(vm, "migrated", false);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                        QEMU_ASYNC_JOB_MIGRATION_IN, stopFlags);
    }

    // end async job of this vm, so that anyoneblocks async job can continue to run
    qemuMigrationJobFinish(driver, vm);
    goto cleanup;
}


/*
 * This version starts an empty VM listening on a localhost TCP port, and
 * sets up the corresponding virStream to handle the incoming data.
 */
int
qemuMigrationDstPrepareTunnel(virQEMUDriverPtr driver,
                              virConnectPtr dconn,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              virStreamPtr st,
                              virDomainDefPtr *def,
                              const char *origname,
                              qemuMigrationParamsPtr migParams,
                              unsigned long flags)
{
    VIR_DEBUG("driver=%p, dconn=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, st=%p, def=%p, "
              "origname=%s, flags=0x%lx",
              driver, dconn, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, st, *def, origname, flags);

    if (st == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("tunnelled migration requested but NULL stream passed"));
        return -1;
    }

    return qemuMigrationDstPrepareAny(driver, dconn, cookiein, cookieinlen,
                                      cookieout, cookieoutlen, def, origname,
                                      st, NULL, 0, false, NULL, 0, NULL, 0,
                                      migParams, flags);
}


static virURIPtr
qemuMigrationAnyParseURI(const char *uri, bool *wellFormed)
{
    char *tmp = NULL;
    virURIPtr parsed;

    /* For compatibility reasons tcp://... URIs are sent as tcp:...
     * We need to transform them to a well-formed URI before parsing. */
    if (STRPREFIX(uri, "tcp:") && !STRPREFIX(uri + 4, "//")) {
        if (virAsprintf(&tmp, "tcp://%s", uri + 4) < 0)
            return NULL;
        uri = tmp;
    }

    parsed = virURIParse(uri);
    if (parsed && wellFormed)
        *wellFormed = !tmp;
    VIR_FREE(tmp);

    return parsed;
}


int
qemuMigrationDstPrepareDirect(virQEMUDriverPtr driver,
                              virConnectPtr dconn,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              const char *uri_in,
                              char **uri_out,
                              virDomainDefPtr *def,
                              const char *origname,
                              const char *listenAddress,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              int nbdPort,
                              qemuMigrationParamsPtr migParams,
                              unsigned long flags)
{
    unsigned short port = 0;
    bool autoPort = true;
    char *hostname = NULL;
    int ret = -1;
    virURIPtr uri = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const char *migrateHost = cfg->migrateHost;

    VIR_DEBUG("driver=%p, dconn=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, uri_in=%s, uri_out=%p, "
              "def=%p, origname=%s, listenAddress=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p, nbdPort=%d, flags=0x%lx",
              driver, dconn, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, NULLSTR(uri_in), uri_out,
              *def, origname, NULLSTR(listenAddress),
              nmigrate_disks, migrate_disks, nbdPort, flags);

    *uri_out = NULL;

    /* The URI passed in may be NULL or a string "tcp://somehostname:port".
     *
     * If the URI passed in is NULL then we allocate a port number
     * from our pool of port numbers, and if the migrateHost is configured,
     * we return a URI of "tcp://migrateHost:port", otherwise return a URI
     * of "tcp://ourhostname:port".
     *
     * If the URI passed in is not NULL then we try to parse out the
     * port number and use that (note that the hostname is assumed
     * to be a correct hostname which refers to the target machine).
     */
    if (uri_in == NULL) {
        // if source libvirtd does not specify the migrateuri
        // we auto migrateuri based on rule above and return it to source
        // so that source will c
        bool encloseAddress = false;
        const char *incFormat;

        // if no migration uri is set by source
        // dst will build it by itself with configration automatically
        //
        // build these if not set by source: protocol:hostname:port
        // port: driver->migrationPorts
        // hostname: GetHostname()
        // protocol: tcp
        if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
            goto cleanup;

        if (migrateHost != NULL) {
            // migration host set by source, use it
            if (virSocketAddrNumericFamily(migrateHost) == AF_INET6)
                encloseAddress = true;

            if (VIR_STRDUP(hostname, migrateHost) < 0)
                goto cleanup;
        } else {
            // get hostname with virGetHostname()
            if ((hostname = virGetHostname()) == NULL)
                goto cleanup;
        }

        if (STRPREFIX(hostname, "localhost")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("hostname on destination resolved to localhost,"
                             " but migration requires an FQDN"));
            goto cleanup;
        }

        /* XXX this really should have been a properly well-formed
         * URI, but we can't add in tcp:// now without breaking
         * compatibility with old targets. We at least make the
         * new targets accept both syntaxes though.
         */
        if (encloseAddress)
            incFormat = "%s:[%s]:%d";
        else
            incFormat = "%s:%s:%d";

        // uri_out will sent to source with tcp:hostname:port
        // source(qemu) must resolve hostname, then connect it for migration!!!
        //
        if (virAsprintf(uri_out, incFormat, "tcp", hostname, port) < 0)
            goto cleanup;
    } else {
        // source provides migration uri, parsse it, then return it back to source
        bool well_formed_uri;

        // migration uri must have scheme:server, port is optional!!!
        if (!(uri = qemuMigrationAnyParseURI(uri_in, &well_formed_uri)))
            goto cleanup;

        if (uri->scheme == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing scheme in migration URI: %s"),
                           uri_in);
            goto cleanup;
        }

        if (STRNEQ(uri->scheme, "tcp") &&
            STRNEQ(uri->scheme, "rdma")) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                           _("unsupported scheme %s in migration URI %s"),
                           uri->scheme, uri_in);
            goto cleanup;
        }

        if (uri->server == NULL) {
            virReportError(VIR_ERR_INVALID_ARG, _("missing host in migration"
                                                  " URI: %s"), uri_in);
            goto cleanup;
        }

        if (uri->port == 0) {
            if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
                goto cleanup;

            /* Send well-formed URI only if uri_in was well-formed */
            if (well_formed_uri) {
                uri->port = port;
                if (!(*uri_out = virURIFormat(uri)))
                    goto cleanup;
            } else {
                if (virAsprintf(uri_out, "%s:%d", uri_in, port) < 0)
                    goto cleanup;
            }
        } else {
            // if user set port autPort is false
            port = uri->port;
            autoPort = false;
        }
    }

    // we will send migration uri_out to source
    if (*uri_out)
        VIR_DEBUG("Generated uri_out=%s", *uri_out);

    // here port is set by source or auto generate based on conf.
    // listenAddress for non-shared disk migration!!!
    ret = qemuMigrationDstPrepareAny(driver, dconn, cookiein, cookieinlen,
                                     cookieout, cookieoutlen, def, origname,
                                     NULL, uri ? uri->scheme : "tcp",
                                     port, autoPort, listenAddress,
                                     nmigrate_disks, migrate_disks, nbdPort,
                                     migParams, flags);
 cleanup:
    virURIFree(uri);
    VIR_FREE(hostname);
    virObjectUnref(cfg);
    if (ret != 0) {
        VIR_FREE(*uri_out);
        if (autoPort)
            virPortAllocatorRelease(port);
    }
    return ret;
}


virDomainDefPtr
qemuMigrationAnyPrepareDef(virQEMUDriverPtr driver,
                           const char *dom_xml,
                           const char *dname,
                           char **origname)
{
    virCapsPtr caps = NULL;
    virDomainDefPtr def;
    char *name = NULL;

    if (!dom_xml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no domain XML passed"));
        return NULL;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        return NULL;

    if (!(def = virDomainDefParseString(dom_xml, caps, driver->xmlopt, NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto cleanup;

    if (dname) {
        name = def->name;
        if (VIR_STRDUP(def->name, dname) < 0) {
            virDomainDefFree(def);
            def = NULL;
        }
    }

 cleanup:
    virObjectUnref(caps);
    if (def && origname)
        *origname = name;
    else
        VIR_FREE(name);
    return def;
}


static int
qemuMigrationSrcConfirmPhase(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             const char *cookiein,
                             int cookieinlen,
                             unsigned int flags,
                             int retcode)
{
    qemuMigrationCookiePtr mig;
    virObjectEventPtr event;
    int rv = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr jobInfo = NULL;

    VIR_DEBUG("driver=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "flags=0x%x, retcode=%d",
              driver, vm, NULLSTR(cookiein), cookieinlen,
              flags, retcode);

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    // retcode returned value of Finish3 operation
    // retcode == 0, dst Finished ok, otherwise it's NOT ok.
    qemuMigrationJobSetPhase(driver, vm,
                             retcode == 0
                             ? QEMU_MIGRATION_PHASE_CONFIRM3
                             : QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED);

    // parse cookies get from FINISH3
    if (!(mig = qemuMigrationEatCookie(driver, vm, cookiein, cookieinlen,
                                       QEMU_MIGRATION_COOKIE_STATS)))
        goto cleanup;

    if (retcode == 0)
        jobInfo = priv->job.completed;
    else
        VIR_FREE(priv->job.completed);

    /* Update times with the values sent by the destination daemon
     * mig->jobInfo is the migration stats sent by remote libvirtd(dst)
     */
    if (mig->jobInfo && jobInfo) {
        //  update completed job stats based on mig->jobInfo got from remote dst!!!
        int reason;

        /* We need to refresh migration statistics after a completed post-copy
         * migration since priv->job.completed contains obsolete data from the
         * time we switched to post-copy mode.
         *
         * when source goes into post-copy(vcpu is stopped, stop event is reported by qemu), it's paused and dst vm runs!!!!
         */
        if (virDomainObjGetState(vm, &reason) == VIR_DOMAIN_PAUSED &&
            reason == VIR_DOMAIN_PAUSED_POSTCOPY &&
            qemuMigrationAnyFetchStats(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                       jobInfo, NULL) < 0)
            VIR_WARN("Could not refresh migration statistics");

        qemuDomainJobInfoUpdateTime(jobInfo);
        // update job stats base on stats sent by remote libvirtd(mig->jobInfo)
        jobInfo->timeDeltaSet = mig->jobInfo->timeDeltaSet;
        jobInfo->timeDelta = mig->jobInfo->timeDelta;
        jobInfo->stats.mig.downtime_set = mig->jobInfo->stats.mig.downtime_set;
        jobInfo->stats.mig.downtime = mig->jobInfo->stats.mig.downtime;
    }

    if (flags & VIR_MIGRATE_OFFLINE)
        goto done;

    /* Did the migration go as planned?  If yes, kill off the domain object.
     * If something failed, resume CPUs, but only if we didn't use post-copy.
     */
    if (retcode == 0) {
        /* If guest uses SPICE and supports seamless migration we have to hold
         * up domain shutdown until SPICE server transfers its data */
        qemuMigrationSrcWaitForSpice(vm);

        // stop vm(destroy vm, kill vm process, actually now vm is 'paused' after migrated) at source as migrated!!!
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_MIGRATED,
                        QEMU_ASYNC_JOB_MIGRATION_OUT,
                        VIR_QEMU_PROCESS_STOP_MIGRATED);
        virDomainAuditStop(vm, "migrated");

        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
        virObjectEventStateQueue(driver->domainEventState, event);
        qemuDomainEventEmitJobCompleted(driver, vm);
    } else {
        virErrorPtr orig_err = virSaveLastError();
        int reason;

        /* cancel any outstanding NBD jobs */
        qemuMigrationSrcNBDCopyCancel(driver, vm, false,
                                      QEMU_ASYNC_JOB_MIGRATION_OUT, NULL);

        virSetError(orig_err);
        virFreeError(orig_err);

        // NOTE: post-copy can leave the source in pause state!!!
        if (virDomainObjGetState(vm, &reason) == VIR_DOMAIN_PAUSED &&
            reason == VIR_DOMAIN_PAUSED_POSTCOPY) {
            qemuMigrationAnyPostcopyFailed(driver, vm);
        } else if (qemuMigrationSrcRestoreDomainState(driver, vm)) {
            // restart vm if it's previous stat is running after migration failed
            event = virDomainEventLifecycleNewFromObj(vm,
                                                      VIR_DOMAIN_EVENT_RESUMED,
                                                      VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
            virObjectEventStateQueue(driver->domainEventState, event);
        }

        // reset migration parameter after migration failed, as we restoring vm state, save it to disk
        // NO need to reset migration parameter after migration ok, as if migration is ok, vm is destroy(kill) at source side!!!
        qemuMigrationParamsReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                 priv->job.migParams, priv->job.apiFlags);

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
    }

 done:
    qemuMigrationCookieFree(mig);
    rv = 0;

 cleanup:
    virObjectUnref(cfg);
    return rv;
}

int
qemuMigrationSrcConfirm(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        const char *cookiein,
                        int cookieinlen,
                        unsigned int flags,
                        int cancelled)
{
    qemuMigrationJobPhase phase;
    virQEMUDriverConfigPtr cfg = NULL;
    int ret = -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_OUT))
        goto cleanup;

    if (cancelled)
        phase = QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED;
    else
        phase = QEMU_MIGRATION_PHASE_CONFIRM3;

    qemuMigrationJobStartPhase(driver, vm, phase);
    virCloseCallbacksUnset(driver->closeCallbacks, vm,
                           qemuMigrationSrcCleanup);

    ret = qemuMigrationSrcConfirmPhase(driver, vm,
                                       cookiein, cookieinlen,
                                       flags, cancelled);

    qemuMigrationJobFinish(driver, vm);
    if (!virDomainObjIsActive(vm)) {
        if (flags & VIR_MIGRATE_UNDEFINE_SOURCE) {
            virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm);
            vm->persistent = 0;
        }
        qemuDomainRemoveInactiveJob(driver, vm);
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}


enum qemuMigrationDestinationType {
    // for tcp, qemu itself connect with remote bind address
    MIGRATION_DEST_HOST,
    // for rdma, libvirtd connect with qemu bind address, then pass it to qemu
    MIGRATION_DEST_CONNECT_HOST,
    // for tunneled case
    MIGRATION_DEST_FD,
};

enum qemuMigrationForwardType {
    // native transport
    MIGRATION_FWD_DIRECT,
    //tunneled
    MIGRATION_FWD_STREAM,
};

typedef struct _qemuMigrationSpec qemuMigrationSpec;
typedef qemuMigrationSpec *qemuMigrationSpecPtr;
struct _qemuMigrationSpec {
    // rdma(MIGRATION_DEST_CONNECT_HOST),
    // tcp(MIGRATION_DEST_HOST),
    // pipe(MIGRATION_DEST_FD)
    enum qemuMigrationDestinationType destType;
    union {
        // native transport
        // migration uri which remote qemu binds to
        struct {
            const char *protocol;
            const char *name;
            int port;
        } host;

        // tunneled, pipe fd
        struct {
            int qemu;
            int local;
        } fd;
    } dest;

    enum qemuMigrationForwardType fwdType;
    union {
        virStreamPtr stream; // for tunneled type, stream is the underlying tcp used for data transfer
    } fwd; // MIGRATION_FWD_DIRECT fwd is not used, as qemu takes care of the stream transfer!!!
};

#define TUNNEL_SEND_BUF_SIZE 65536

typedef struct _qemuMigrationIOThread qemuMigrationIOThread;
typedef qemuMigrationIOThread *qemuMigrationIOThreadPtr;
struct _qemuMigrationIOThread {
    virThread thread;
    virStreamPtr st;
    int sock;
    virError err;
    int wakeupRecvFD;
    int wakeupSendFD;
};

static void qemuMigrationSrcIOFunc(void *arg)
{
    qemuMigrationIOThreadPtr data = arg;
    char *buffer = NULL;
    struct pollfd fds[2];
    int timeout = -1;
    virErrorPtr err = NULL;

    VIR_DEBUG("Running migration tunnel; stream=%p, sock=%d",
              data->st, data->sock);

    if (VIR_ALLOC_N(buffer, TUNNEL_SEND_BUF_SIZE) < 0)
        goto abrt;

    // data->sock is the read side of pipe for migration data from qemu
    fds[0].fd = data->sock;
    fds[1].fd = data->wakeupRecvFD;

    for (;;) {
        int ret;

        fds[0].events = fds[1].events = POLLIN;
        fds[0].revents = fds[1].revents = 0;

        ret = poll(fds, ARRAY_CARDINALITY(fds), timeout);

        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            virReportSystemError(errno, "%s",
                                 _("poll failed in migration tunnel"));
            goto abrt;
        }

        if (ret == 0) {
            /* We were asked to gracefully stop but reading would block. This
             * can only happen if qemu told us migration finished but didn't
             * close the migration fd. We handle this in the same way as EOF.
             */
            VIR_DEBUG("QEMU forgot to close migration fd");
            break;
        }

        if (fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
            char stop = 0;

            if (saferead(data->wakeupRecvFD, &stop, 1) != 1) {
                virReportSystemError(errno, "%s",
                                     _("failed to read from wakeup fd"));
                goto abrt;
            }

            VIR_DEBUG("Migration tunnel was asked to %s",
                      stop ? "abort" : "finish");
            if (stop) {
                goto abrt;
            } else {
                timeout = 0;
            }
        }

        if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
            int nbytes;

            // get migration data from qemu at source host
            nbytes = saferead(data->sock, buffer, TUNNEL_SEND_BUF_SIZE);
            if (nbytes > 0) {
                // send the data from stream connection which is same connection as migration rpc call
                if (virStreamSend(data->st, buffer, nbytes) < 0)
                    goto error;
            } else if (nbytes < 0) {
                virReportSystemError(errno, "%s",
                        _("tunnelled migration failed to read from qemu"));
                goto abrt;
            } else {
                /* EOF; get out of here */
                break;
            }
        }
    }

    if (virStreamFinish(data->st) < 0)
        goto error;

    VIR_FORCE_CLOSE(data->sock);
    VIR_FREE(buffer);

    return;

 abrt:
    err = virSaveLastError();
    if (err && err->code == VIR_ERR_OK) {
        virFreeError(err);
        err = NULL;
    }
    virStreamAbort(data->st);
    if (err) {
        virSetError(err);
        virFreeError(err);
    }

 error:
    /* Let the source qemu know that the transfer cant continue anymore.
     * Don't copy the error for EPIPE as destination has the actual error. */
    VIR_FORCE_CLOSE(data->sock);
    if (!virLastErrorIsSystemErrno(EPIPE))
        virCopyLastError(&data->err);
    virResetLastError();
    VIR_FREE(buffer);
}


static qemuMigrationIOThreadPtr
qemuMigrationSrcStartTunnel(virStreamPtr st,
                            int sock)
{
    qemuMigrationIOThreadPtr io = NULL;
    int wakeupFD[2] = { -1, -1 };

    if (pipe2(wakeupFD, O_CLOEXEC) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to make pipe"));
        goto error;
    }

    if (VIR_ALLOC(io) < 0)
        goto error;

    io->st = st;
    io->sock = sock;
    io->wakeupRecvFD = wakeupFD[0];
    io->wakeupSendFD = wakeupFD[1];

    // libvirt io thread not belongs to rpc thread pool or qemu thread!!!
    if (virThreadCreate(&io->thread, true,
                        qemuMigrationSrcIOFunc,
                        io) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create migration thread"));
        goto error;
    }

    return io;

 error:
    VIR_FORCE_CLOSE(wakeupFD[0]);
    VIR_FORCE_CLOSE(wakeupFD[1]);
    VIR_FREE(io);
    return NULL;
}

static int
qemuMigrationSrcStopTunnel(qemuMigrationIOThreadPtr io, bool error)
{
    int rv = -1;
    char stop = error ? 1 : 0;

    /* make sure the thread finishes its job and is joinable */
    if (safewrite(io->wakeupSendFD, &stop, 1) != 1) {
        virReportSystemError(errno, "%s",
                             _("failed to wakeup migration tunnel"));
        goto cleanup;
    }

    virThreadJoin(&io->thread);

    /* Forward error from the IO thread, to this thread */
    if (io->err.code != VIR_ERR_OK) {
        if (error)
            rv = 0;
        else
            virSetError(&io->err);
        virResetError(&io->err);
        goto cleanup;
    }

    rv = 0;

 cleanup:
    VIR_FORCE_CLOSE(io->wakeupSendFD);
    VIR_FORCE_CLOSE(io->wakeupRecvFD);
    VIR_FREE(io);
    return rv;
}

static int
qemuMigrationSrcConnect(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        qemuMigrationSpecPtr spec)
{
    virNetSocketPtr sock;
    const char *host;
    char *port = NULL;
    int ret = -1;

    host = spec->dest.host.name;
    if (virAsprintf(&port, "%d", spec->dest.host.port) < 0)
        return -1;

    spec->destType = MIGRATION_DEST_FD;
    spec->dest.fd.qemu = -1;

    if (qemuSecuritySetSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;
    if (virNetSocketNewConnectTCP(host, port,
                                  AF_UNSPEC,
                                  &sock) == 0) {
        // save the fd to spec
        spec->dest.fd.qemu = virNetSocketDupFD(sock, true);
        virObjectUnref(sock);
    }
    if (qemuSecurityClearSocketLabel(driver->securityManager, vm->def) < 0 ||
        spec->dest.fd.qemu == -1)
        goto cleanup;

    /* Migration expects a blocking FD */
    if (virSetBlocking(spec->dest.fd.qemu, true) < 0) {
        virReportSystemError(errno, _("Unable to set FD %d blocking"),
                             spec->dest.fd.qemu);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(port);
    if (ret < 0)
        VIR_FORCE_CLOSE(spec->dest.fd.qemu);
    return ret;
}


static int
qemuMigrationSrcContinue(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuMonitorMigrationStatus status,
                         qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorMigrateContinue(priv->mon, status);

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    return ret;
}


static int
qemuMigrationSrcRun(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    const char *persist_xml,
                    const char *cookiein,
                    int cookieinlen,
                    char **cookieout,
                    int *cookieoutlen,
                    unsigned long flags,
                    unsigned long resource,
                    qemuMigrationSpecPtr spec,
                    virConnectPtr dconn,
                    const char *graphicsuri,
                    size_t nmigrate_disks,
                    const char **migrate_disks,
                    qemuMigrationParamsPtr migParams)
{
    int ret = -1;
    unsigned int migrate_flags = QEMU_MONITOR_MIGRATE_BACKGROUND;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMigrationCookiePtr mig = NULL;
    char *tlsAlias = NULL;
    qemuMigrationIOThreadPtr iothread = NULL;
    int fd = -1;
    unsigned long migrate_speed = resource ? resource : priv->migMaxBandwidth;
    virErrorPtr orig_err = NULL;
    unsigned int cookieFlags = 0;
    bool abort_on_error = !!(flags & VIR_MIGRATE_ABORT_ON_ERROR);
    bool events = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT);
    bool cancel = false;
    unsigned int waitFlags;
    virDomainDefPtr persistDef = NULL;
    char *timestamp;
    int rc;

    VIR_DEBUG("driver=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=0x%lx, resource=%lu, "
              "spec=%p (dest=%d, fwd=%d), dconn=%p, graphicsuri=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p",
              driver, vm, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              spec, spec->destType, spec->fwdType, dconn,
              NULLSTR(graphicsuri), nmigrate_disks, migrate_disks);

    if (flags & VIR_MIGRATE_NON_SHARED_DISK) {
        // migrate_flags tell source qemu what to migration(disk here) by QMP command
        migrate_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_DISK;
        // cookie tell what cookie I will sent to peer.
        cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_INC) {
        migrate_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_INC;
        cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    }

    if (virLockManagerPluginUsesState(driver->lockManager) &&
        !cookieout) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Migration with lock driver %s requires"
                         " cookie support"),
                       virLockManagerPluginGetName(driver->lockManager));
        return -1;
    }

    if (events)
        priv->signalIOError = abort_on_error;

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        // if persistent on target, here we generate the persistentDef
        // and send it by cookie when Finish3 phase !!!
        if (persist_xml) {
            if (!(persistDef = qemuMigrationAnyPrepareDef(driver, persist_xml,
                                                          NULL, NULL)))
                goto error;
        } else {
            virDomainDefPtr def = vm->newDef ? vm->newDef : vm->def;
            if (!(persistDef = qemuDomainDefCopy(driver, def,
                                                 VIR_DOMAIN_XML_SECURE |
                                                 VIR_DOMAIN_XML_MIGRATABLE)))
                goto error;
        }
    }

    mig = qemuMigrationEatCookie(driver, vm, cookiein, cookieinlen,
                                 cookieFlags |
                                 QEMU_MIGRATION_COOKIE_GRAPHICS |
                                 QEMU_MIGRATION_COOKIE_CAPS);
    if (!mig)
        goto error;

    if (qemuMigrationSrcGraphicsRelocate(driver, vm, mig, graphicsuri) < 0)
        VIR_WARN("unable to provide data for graphics client relocation");

    if (qemuMigrationParamsCheck(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                 migParams, mig->caps->automatic) < 0)
        goto error;

    // set tls in migration parameter
    if (flags & VIR_MIGRATE_TLS) {
        const char *hostname = NULL;

        /* We need to add tls-hostname whenever QEMU itself does not
         * connect directly to the destination. */
        if (spec->destType == MIGRATION_DEST_CONNECT_HOST ||
            spec->destType == MIGRATION_DEST_FD)
            hostname = spec->dest.host.name;

        if (qemuMigrationParamsEnableTLS(driver, vm, false,
                                         QEMU_ASYNC_JOB_MIGRATION_OUT,
                                         &tlsAlias, hostname,
                                         migParams) < 0)
            goto error;
    } else {
        if (qemuMigrationParamsDisableTLS(vm, migParams) < 0)
            goto error;
    }

    // set migration parameter at source libvirtd by QMP
    if (qemuMigrationParamsApply(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                 migParams) < 0)
        goto error;

    if (migrate_flags & (QEMU_MONITOR_MIGRATE_NON_SHARED_DISK |
                         QEMU_MONITOR_MIGRATE_NON_SHARED_INC)) {
        if (mig->nbd) {
            /* Currently libvirt does not support setting up of the NBD
             * non-shared storage migration with TLS. As we need to honour the
             * VIR_MIGRATE_TLS flag, we need to reject such migration until
             * we implement TLS for NBD. */
            if (flags & VIR_MIGRATE_TLS &&
                !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV_DEL)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("NBD migration with TLS is not supported"));
                goto error;
            }

            /* This will update migrate_flags on success, prepare disk mirror
             * for each disk to migration
             */
            if (qemuMigrationSrcNBDStorageCopy(driver, vm, mig,
                                               spec->dest.host.name,
                                               migrate_speed,
                                               &migrate_flags,
                                               nmigrate_disks,
                                               migrate_disks,
                                               dconn, tlsAlias, flags) < 0) {
                goto error;
            }
        } else {
            /* Destination doesn't support NBD server.
             * Fall back to previous implementation. */
            VIR_DEBUG("Destination doesn't support NBD server "
                      "Falling back to previous implementation.");
        }
    }

    /* Before EnterMonitor, since qemuMigrationSetOffline already does that */
    if (!(flags & VIR_MIGRATE_LIVE) &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (qemuMigrationSrcSetOffline(driver, vm) < 0)
            goto error;
    }

    // get monitor lock and free vm lock!!!
    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto error;

    if (priv->job.abortJob) {
        /* explicitly do this *after* we entered the monitor,
         * as this is a critical section so we are guaranteed
         * priv->job.abortJob will not change */
        priv->job.current->status = QEMU_DOMAIN_JOB_STATUS_CANCELED;
        virReportError(VIR_ERR_OPERATION_ABORTED, _("%s: %s"),
                       qemuDomainAsyncJobTypeToString(priv->job.asyncActive),
                       _("canceled by client"));
        goto exit_monitor;
    }

    // set migration speed at source host by QMP even async migration job is there
    // as it's mask allowing MIGRATION_OP!!!
    if (qemuMonitorSetMigrationSpeed(priv->mon, migrate_speed) < 0)
        goto exit_monitor;

    /* rdma: connect to the destination qemu if needed */
    if (spec->destType == MIGRATION_DEST_CONNECT_HOST &&
        qemuMigrationSrcConnect(driver, vm, spec) < 0) {
        goto exit_monitor;
    }

    /* log start of migration */
    if ((timestamp = virTimeStringNow()) != NULL) {
        qemuDomainLogAppendMessage(driver, vm, "%s: initiating migration\n", timestamp);
        VIR_FREE(timestamp);
    }

    rc = -1;
    switch (spec->destType) {
    // tcp:
    case MIGRATION_DEST_HOST:
        if (STREQ(spec->dest.host.protocol, "rdma") &&
            virProcessSetMaxMemLock(vm->pid, vm->def->mem.hard_limit << 10) < 0) {
            goto exit_monitor;
        }
        // start migration with remote by send QMP command to source qemu
        // later on qemu will start conect with remote qemu process with protocol:host:port
        // and migration starts between two qemu-processed on different hosts
        //
        // here only trigger migrate QMP command
        rc = qemuMonitorMigrateToHost(priv->mon, migrate_flags,
                                      spec->dest.host.protocol,
                                      spec->dest.host.name,
                                      spec->dest.host.port);
        break;

     // rdma:
    case MIGRATION_DEST_CONNECT_HOST:
        /* handled above and transformed into MIGRATION_DEST_FD */
        break;

    case MIGRATION_DEST_FD:
        // for tunneled case
        if (spec->fwdType != MIGRATION_FWD_DIRECT) {
            fd = spec->dest.fd.local; // read side of pipe at source
            spec->dest.fd.local = -1;
        }
        // for tunneled, we send write side of pipe(fd passed) to qemu for writing!!!
        // in libivrtd we read from read side fd.local
        rc = qemuMonitorMigrateToFd(priv->mon, migrate_flags,
                                    spec->dest.fd.qemu);
        VIR_FORCE_CLOSE(spec->dest.fd.qemu);
        break;
    }

    // get vm lock(vm lock protects monitor as well) and free monitor lock which is small
    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
        goto error;

    /* From this point onwards we *must* call cancel to abort the
     * migration on source if anything goes wrong */
    cancel = true;

    if (spec->fwdType != MIGRATION_FWD_DIRECT) {
        // iothread info based on stream and read pipe(tunnel thread for data transfer)
        if (!(iothread = qemuMigrationSrcStartTunnel(spec->fwd.stream, fd)))
            goto error;
        /* If we've created a tunnel, then the 'fd' will be closed in the
         * qemuMigrationIOFunc as data->sock.
         */
        fd = -1;
    }

    waitFlags = QEMU_MIGRATION_COMPLETED_PRE_SWITCHOVER;
    if (abort_on_error)
        waitFlags |= QEMU_MIGRATION_COMPLETED_ABORT_ON_ERROR;
    if (mig->nbd)
        waitFlags |= QEMU_MIGRATION_COMPLETED_CHECK_STORAGE;
    if (flags & VIR_MIGRATE_POSTCOPY)
        waitFlags |= QEMU_MIGRATION_COMPLETED_POSTCOPY;

    // wait for migration until finish block here at source side.
    // returns
    // 1. error
    // 2. postcopy
    // 3. completed
    rc = qemuMigrationSrcWaitForCompletion(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT,
                                           dconn, waitFlags);
    if (rc == -2) {
        goto error;
    } else if (rc == -1) {
        /* QEMU reported failed migration, nothing to cancel anymore */
        cancel = false;
        goto error;
    }

    /* When migration completed, QEMU will have paused the CPUs for us.
     * Wait for the STOP event to be processed or explicitly stop CPUs
     * (for old QEMU which does not send events) to release the lock state.
     */
    if (priv->monJSON) {
        // migration: post-copy or completed, a STOP event will be reported by qemu to libvirtd
        while (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
            // stop vm at source when migration finish
            priv->signalStop = true;
            // block here, wake up due to STOP event
            rc = virDomainObjWait(vm);
            priv->signalStop = false;
            if (rc < 0)
                goto error;
        }
    } else if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING &&
               qemuMigrationSrcSetOffline(driver, vm) < 0) {
        goto error;
    }

    // cancel drive mirror as we setup drive mirror for non-storage migration
    // here we remove that mirror
    if (mig->nbd &&
        qemuMigrationSrcNBDCopyCancel(driver, vm, true,
                                      QEMU_ASYNC_JOB_MIGRATION_OUT,
                                      dconn) < 0)
        goto error;

    /* When migration was paused before serializing device state we need to
     * resume it now once we finished all block jobs and wait for the real
     * end of the migration.
     */
    if (priv->job.current->status == QEMU_DOMAIN_JOB_STATUS_PAUSED) {
        // migration will be paused if block job runs for disk
        // here we continue migration with QMP 'migrate-continue' if it's paused
        if (qemuMigrationSrcContinue(driver, vm,
                                     QEMU_MONITOR_MIGRATION_STATUS_PRE_SWITCHOVER,
                                     QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto error;

        waitFlags ^= QEMU_MIGRATION_COMPLETED_PRE_SWITCHOVER;

        // wait migration completed after we resume migration.
        rc = qemuMigrationSrcWaitForCompletion(driver, vm,
                                               QEMU_ASYNC_JOB_MIGRATION_OUT,
                                               dconn, waitFlags);
        if (rc == -2) {
            goto error;
        } else if (rc == -1) {
            /* QEMU reported failed migration, nothing to cancel anymore */
            cancel = false;
            goto error;
        }
    }

    if (iothread) {
        qemuMigrationIOThreadPtr io;

        VIR_STEAL_PTR(io, iothread);
        // stop iothread which sending data for tunneled case
        if (qemuMigrationSrcStopTunnel(io, false) < 0)
            goto error;
    }

    if (priv->job.completed) {
        // update migration time at source side
        priv->job.completed->stopped = priv->job.current->stopped;
        qemuDomainJobInfoUpdateTime(priv->job.completed);
        qemuDomainJobInfoUpdateDowntime(priv->job.completed);
        ignore_value(virTimeMillisNow(&priv->job.completed->sent));
    }

    cookieFlags |= QEMU_MIGRATION_COOKIE_NETWORK |
                   QEMU_MIGRATION_COOKIE_STATS;

    // add persistenDef to cookie that will be sent to dst at next phase FINISH3
    if (qemuMigrationCookieAddPersistent(mig, &persistDef) < 0 ||
        qemuMigrationBakeCookie(mig, driver, vm,
                                QEMU_MIGRATION_SOURCE,
                                cookieout, cookieoutlen, cookieFlags) < 0) {
        VIR_WARN("Unable to encode migration cookie");
    }

    ret = 0;

 cleanup:
    VIR_FREE(tlsAlias);
    VIR_FORCE_CLOSE(fd);
    virDomainDefFree(persistDef);
    qemuMigrationCookieFree(mig);

    if (events)
        priv->signalIOError = false;

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

    return ret;

 error:
    orig_err = virSaveLastError();

    if (virDomainObjIsActive(vm)) {
        if (cancel &&
            priv->job.current->status != QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED &&
            qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT) == 0) {
            //for error send QMP:  "migrate_cancel"
            qemuMonitorMigrateCancel(priv->mon);
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
        }

        /* cancel any outstanding NBD jobs */
        if (mig && mig->nbd)
            qemuMigrationSrcNBDCopyCancel(driver, vm, false,
                                          QEMU_ASYNC_JOB_MIGRATION_OUT,
                                          dconn);

        if (priv->job.current->status != QEMU_DOMAIN_JOB_STATUS_CANCELED)
            priv->job.current->status = QEMU_DOMAIN_JOB_STATUS_FAILED;
    }

    if (iothread)
        qemuMigrationSrcStopTunnel(iothread, true);

    goto cleanup;

 exit_monitor:
    ignore_value(qemuDomainObjExitMonitor(driver, vm));
    goto error;
}

/* Perform migration using QEMU's native migrate support,
 * not encrypted obviously
 */
static int
qemuMigrationSrcPerformNative(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              const char *persist_xml,
                              const char *uri,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              unsigned long flags,
                              unsigned long resource,
                              virConnectPtr dconn,
                              const char *graphicsuri,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              qemuMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virURIPtr uribits = NULL;
    int ret = -1;
    qemuMigrationSpec spec;

    VIR_DEBUG("driver=%p, vm=%p, uri=%s, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=0x%lx, resource=%lu, "
              "graphicsuri=%s, nmigrate_disks=%zu migrate_disks=%p",
              driver, vm, uri, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              NULLSTR(graphicsuri), nmigrate_disks, migrate_disks);

    // uri is the migration uri sent back by dst libvirtd
    // parse uri from string
    if (!(uribits = qemuMigrationAnyParseURI(uri, NULL)))
        return -1;

    if (uribits->scheme == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing scheme in migration URI: %s"),
                       uri);
        goto cleanup;
    }

    if (STREQ(uribits->scheme, "rdma")) {
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_RDMA)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("outgoing RDMA migration is not supported "
                             "with this QEMU binary"));
            goto cleanup;
        }
        if (!virMemoryLimitIsSet(vm->def->mem.hard_limit)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot start RDMA migration with no memory hard "
                             "limit set"));
            goto cleanup;
        }
    }

    if (STRNEQ(uribits->scheme, "rdma"))
        spec.destType = MIGRATION_DEST_CONNECT_HOST;
    else
        spec.destType = MIGRATION_DEST_HOST;

    spec.dest.host.protocol = uribits->scheme;
    spec.dest.host.name = uribits->server;
    spec.dest.host.port = uribits->port;
    spec.fwdType = MIGRATION_FWD_DIRECT;

    ret = qemuMigrationSrcRun(driver, vm, persist_xml, cookiein, cookieinlen, cookieout,
                              cookieoutlen, flags, resource, &spec, dconn,
                              graphicsuri, nmigrate_disks, migrate_disks,
                              migParams);

    if (spec.destType == MIGRATION_DEST_FD)
        VIR_FORCE_CLOSE(spec.dest.fd.qemu);

 cleanup:
    virURIFree(uribits);

    return ret;
}


static int
qemuMigrationSrcPerformTunnel(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virStreamPtr st,
                              const char *persist_xml,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              unsigned long flags,
                              unsigned long resource,
                              virConnectPtr dconn,
                              const char *graphicsuri,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              qemuMigrationParamsPtr migParams)
{
    int ret = -1;
    qemuMigrationSpec spec;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int fds[2] = { -1, -1 };

    VIR_DEBUG("driver=%p, vm=%p, st=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=0x%lx, resource=%lu, "
              "graphicsuri=%s, nmigrate_disks=%zu, migrate_disks=%p",
              driver, vm, st, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              NULLSTR(graphicsuri), nmigrate_disks, migrate_disks);

    spec.fwdType = MIGRATION_FWD_STREAM;
    spec.fwd.stream = st;


    spec.destType = MIGRATION_DEST_FD;
    spec.dest.fd.qemu = -1;
    spec.dest.fd.local = -1;

    // create a pipe at source host as well
    if (pipe2(fds, O_CLOEXEC) == 0) {
        spec.dest.fd.qemu = fds[1];  // write side passed to qemu
        spec.dest.fd.local = fds[0]; // read side
    }
    if (spec.dest.fd.qemu == -1 ||
        qemuSecuritySetImageFDLabel(driver->securityManager, vm->def,
                                    spec.dest.fd.qemu) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot create pipe for tunnelled migration"));
        goto cleanup;
    }

    ret = qemuMigrationSrcRun(driver, vm, persist_xml, cookiein, cookieinlen,
                              cookieout, cookieoutlen, flags, resource, &spec,
                              dconn, graphicsuri, nmigrate_disks, migrate_disks,
                              migParams);

 cleanup:
    VIR_FORCE_CLOSE(spec.dest.fd.qemu);
    VIR_FORCE_CLOSE(spec.dest.fd.local);

    virObjectUnref(cfg);
    return ret;
}


/* This is essentially a re-impl of virDomainMigrateVersion2
 * from libvirt.c, but running in source libvirtd context,
 * instead of client app context & also adding in tunnel
 * handling */
static int
qemuMigrationSrcPerformPeer2Peer2(virQEMUDriverPtr driver,
                                  virConnectPtr sconn,
                                  virConnectPtr dconn,
                                  virDomainObjPtr vm,
                                  const char *dconnuri,
                                  unsigned long flags,
                                  const char *dname,
                                  unsigned long resource,
                                  qemuMigrationParamsPtr migParams)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookie = NULL;
    char *dom_xml = NULL;
    int cookielen = 0, ret;
    virErrorPtr orig_err = NULL;
    bool cancelled;
    virStreamPtr st = NULL;
    unsigned long destflags;

    VIR_DEBUG("driver=%p, sconn=%p, dconn=%p, vm=%p, dconnuri=%s, "
              "flags=0x%lx, dname=%s, resource=%lu",
              driver, sconn, dconn, vm, NULLSTR(dconnuri),
              flags, NULLSTR(dname), resource);

    /* In version 2 of the protocol, the prepare step is slightly
     * different.  We fetch the domain XML of the source domain
     * and pass it to Prepare2.
     */
    if (!(dom_xml = qemuDomainFormatXML(driver, vm,
                                        QEMU_DOMAIN_FORMAT_LIVE_FLAGS |
                                        VIR_DOMAIN_XML_MIGRATABLE)))
        return -1;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~(VIR_MIGRATE_ABORT_ON_ERROR |
                          VIR_MIGRATE_AUTO_CONVERGE);

    VIR_DEBUG("Prepare2 %p", dconn);
    if (flags & VIR_MIGRATE_TUNNELLED) {
        /*
         * Tunnelled Migrate Version 2 does not support cookies
         * due to missing parameters in the prepareTunnel() API.
         */

        if (!(st = virStreamNew(dconn, 0)))
            goto cleanup;

        qemuDomainObjEnterRemote(vm);
        ret = dconn->driver->domainMigratePrepareTunnel
            (dconn, st, destflags, dname, resource, dom_xml);
        if (qemuDomainObjExitRemote(vm, true) < 0)
            goto cleanup;
    } else {
        qemuDomainObjEnterRemote(vm);
        ret = dconn->driver->domainMigratePrepare2
            (dconn, &cookie, &cookielen, NULL, &uri_out,
             destflags, dname, resource, dom_xml);
        if (qemuDomainObjExitRemote(vm, true) < 0)
            goto cleanup;
    }
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto cleanup;

    if (!(flags & VIR_MIGRATE_TUNNELLED) &&
        (uri_out == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare2 did not set uri"));
        cancelled = true;
        orig_err = virSaveLastError();
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    VIR_DEBUG("Perform %p", sconn);
    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM2);
    if (flags & VIR_MIGRATE_TUNNELLED)
        ret = qemuMigrationSrcPerformTunnel(driver, vm, st, NULL,
                                            NULL, 0, NULL, NULL,
                                            flags, resource, dconn,
                                            NULL, 0, NULL, migParams);
    else
        ret = qemuMigrationSrcPerformNative(driver, vm, NULL, uri_out,
                                            cookie, cookielen,
                                            NULL, NULL, /* No out cookie with v2 migration */
                                            flags, resource, dconn, NULL, 0, NULL,
                                            migParams);

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0)
        orig_err = virSaveLastError();

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0;

 finish:
    /* In version 2 of the migration protocol, we pass the
     * status code from the sender to the destination host,
     * so it can do any cleanup if the migration failed.
     */
    dname = dname ? dname : vm->def->name;
    VIR_DEBUG("Finish2 %p ret=%d", dconn, ret);
    qemuDomainObjEnterRemote(vm);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, cookie, cookielen,
         uri_out ? uri_out : dconnuri, destflags, cancelled);
    /* The domain is already gone at this point */
    ignore_value(qemuDomainObjExitRemote(vm, false));
    if (cancelled && ddomain)
        VIR_ERROR(_("finish step ignored that migration was cancelled"));

 cleanup:
    if (ddomain) {
        virObjectUnref(ddomain);
        ret = 0;
    } else {
        ret = -1;
    }

    virObjectUnref(st);

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE(uri_out);
    VIR_FREE(cookie);

    return ret;
}


/* This is essentially a re-impl of virDomainMigrateVersion3
 * from libvirt.c, but running in source libvirtd context,
 * instead of client app context & also adding in tunnel
 * handling */
static int
qemuMigrationSrcPerformPeer2Peer3(virQEMUDriverPtr driver,
                                  virConnectPtr sconn,
                                  virConnectPtr dconn,
                                  const char *dconnuri,
                                  virDomainObjPtr vm,
                                  const char *xmlin,
                                  const char *persist_xml,
                                  const char *dname,
                                  const char *uri,
                                  const char *graphicsuri,
                                  const char *listenAddress,
                                  size_t nmigrate_disks,
                                  const char **migrate_disks,
                                  int nbdPort,
                                  qemuMigrationParamsPtr migParams,
                                  unsigned long long bandwidth,
                                  bool useParams,
                                  unsigned long flags)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookiein = NULL;
    char *cookieout = NULL;
    char *dom_xml = NULL;
    int cookieinlen = 0;
    int cookieoutlen = 0;
    int ret = -1;
    virErrorPtr orig_err = NULL;
    bool cancelled = true;
    virStreamPtr st = NULL;
    unsigned long destflags;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    size_t i;
    bool offline = !!(flags & VIR_MIGRATE_OFFLINE);

    VIR_DEBUG("driver=%p, sconn=%p, dconn=%p, dconnuri=%s, vm=%p, xmlin=%s, "
              "dname=%s, uri=%s, graphicsuri=%s, listenAddress=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p, nbdPort=%d, "
              "bandwidth=%llu, useParams=%d, flags=0x%lx",
              driver, sconn, dconn, NULLSTR(dconnuri), vm, NULLSTR(xmlin),
              NULLSTR(dname), NULLSTR(uri), NULLSTR(graphicsuri),
              NULLSTR(listenAddress), nmigrate_disks, migrate_disks, nbdPort,
              bandwidth, useParams, flags);

    /* Unlike the virDomainMigrateVersion3 counterpart, we don't need
     * to worry about auto-setting the VIR_MIGRATE_CHANGE_PROTECTION
     * bit here, because we are already running inside the context of
     * a single job.  */

    // generate migration cookie at source and dump xml of this vm(or use it from pased in xmlin)
    // dom_xml used for new vm at remote libivrtd
    // cookieout: migration information sent to remote libvirtd, onside bake cookie, the other side eat it
    dom_xml = qemuMigrationSrcBeginPhase(driver, vm, xmlin, dname,
                                         &cookieout, &cookieoutlen,
                                         nmigrate_disks, migrate_disks, flags);
    if (!dom_xml)
        goto cleanup;

    if (useParams) {
        // build parameters from separate variables!!!
        // remote libvirtd supports migration parameter (v3 extenions)
        // add dom_xml from user or vm->def to migration parameter that will be transferred to dst host
        // use it to create a new vm
        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_DEST_XML, dom_xml) < 0)
            goto cleanup;

        if (dname &&
            virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_DEST_NAME, dname) < 0)
            goto cleanup;

        if (uri &&
            virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_URI, uri) < 0)
            goto cleanup;

        if (bandwidth &&
            virTypedParamsAddULLong(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_BANDWIDTH,
                                    bandwidth) < 0)
            goto cleanup;

        if (graphicsuri &&
            virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_GRAPHICS_URI,
                                    graphicsuri) < 0)
            goto cleanup;
        if (listenAddress &&
            virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_LISTEN_ADDRESS,
                                    listenAddress) < 0)
            goto cleanup;
        for (i = 0; i < nmigrate_disks; i++)
            if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                        VIR_MIGRATE_PARAM_MIGRATE_DISKS,
                                        migrate_disks[i]) < 0)
                goto cleanup;
        if (nbdPort &&
            virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_DISKS_PORT,
                                 nbdPort) < 0)
            goto cleanup;

        if (qemuMigrationParamsDump(migParams, &params, &nparams,
                                    &maxparams, &flags) < 0)
            goto cleanup;
    }

    // if source is paused, we pass PAUSE to dst as well, so that it will not start vm at dst
    // that means after migration, vm is paused at dst, shutoff at source.
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;
    // flags comes from user with extra we added during processing at source side
    // abort on error and auto converge are used only on source side, hence remove it when passing flags to remote libvirtd

    destflags = flags & ~(VIR_MIGRATE_ABORT_ON_ERROR |
                          VIR_MIGRATE_AUTO_CONVERGE);

    VIR_DEBUG("Prepare3 %p", dconn);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (flags & VIR_MIGRATE_TUNNELLED) {
        // for tunneled, stream is based on dconnection as well
        // that means dconn is used for control(migration rpc) and data transport!!!
        if (!(st = virStreamNew(dconn, 0)))
            goto cleanup;

        qemuDomainObjEnterRemote(vm);
        if (useParams) {
            ret = dconn->driver->domainMigratePrepareTunnel3Params
                (dconn, st, params, nparams, cookiein, cookieinlen,
                 &cookieout, &cookieoutlen, destflags);
        } else {
            ret = dconn->driver->domainMigratePrepareTunnel3
                (dconn, st, cookiein, cookieinlen, &cookieout, &cookieoutlen,
                 destflags, dname, bandwidth, dom_xml);
        }
        if (qemuDomainObjExitRemote(vm, !offline) < 0)
            goto cleanup;
    } else {
        qemuDomainObjEnterRemote(vm);
        // as we will do rpc all, release vm lock temporary.
        if (useParams) {
            // we pass cookiein and params, destflags to remote libvirtd
            // prepare at dst call prepare3 rpc call!!!
            //
            // with dst prepared, we got uri_out(migration uri) and cookieout
            ret = dconn->driver->domainMigratePrepare3Params
                (dconn, params, nparams, cookiein, cookieinlen,
                 &cookieout, &cookieoutlen, &uri_out, destflags);
        } else {
            ret = dconn->driver->domainMigratePrepare3
                (dconn, cookiein, cookieinlen, &cookieout, &cookieoutlen,
                 uri, &uri_out, destflags, dname, bandwidth, dom_xml);
        }
        // vm lock is got here
        if (qemuDomainObjExitRemote(vm, !offline) < 0)
            goto cleanup;
    }
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto cleanup;

    if (offline) {
        VIR_DEBUG("Offline migration, skipping Perform phase");
        VIR_FREE(cookieout);
        cookieoutlen = 0;
        cancelled = false;
        goto finish;
    }

    if (uri_out) {
        // get migration uri return by remote libvirtd
        uri = uri_out;
        if (useParams &&
            // update migration uri set in parameter
            virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_URI, uri_out) < 0) {
            orig_err = virSaveLastError();
            goto finish;
        }
    } else if (!uri && !(flags & VIR_MIGRATE_TUNNELLED)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare3 did not set uri"));
        orig_err = virSaveLastError();
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete. The src VM should remain
     * running, but in paused state until the destination can
     * confirm migration completion.
     */
    VIR_DEBUG("Perform3 %p uri=%s", sconn, NULLSTR(uri));
    // after prepare at dst, we step in perform3 phase here.
    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM3);
    VIR_FREE(cookiein);
    // use the cookie sent by remote libvirt when rpc prepare3 as next cookiein
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (flags & VIR_MIGRATE_TUNNELLED) {
        ret = qemuMigrationSrcPerformTunnel(driver, vm, st, persist_xml,
                                            cookiein, cookieinlen,
                                            &cookieout, &cookieoutlen,
                                            flags, bandwidth, dconn, graphicsuri,
                                            nmigrate_disks, migrate_disks,
                                            migParams);
    } else {
        // perform native migration, block until migration finished,
        // no rpc call for perform, only source trigger migration by QMP and wait for its completion
        // cookieout generated by source libvirtd based on cookiein
        ret = qemuMigrationSrcPerformNative(driver, vm, persist_xml, uri,
                                            cookiein, cookieinlen,
                                            &cookieout, &cookieoutlen,
                                            flags, bandwidth, dconn, graphicsuri,
                                            nmigrate_disks, migrate_disks,
                                            migParams);
    }

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0) {
        orig_err = virSaveLastError();
    } else {
        // if migration completed, set phase to PERFORM3_DONE
        qemuMigrationJobSetPhase(driver, vm,
                                 QEMU_MIGRATION_PHASE_PERFORM3_DONE);
    }

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0;

 finish:
    /*
     * The status code from the source is passed to the destination.
     * The dest can cleanup in the source indicated it failed to
     * send all migration data. Returns NULL for ddomain if
     * the dest was unable to complete migration.
     */
    VIR_DEBUG("Finish3 %p ret=%d", dconn, ret);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;

    if (useParams) {
        if (virTypedParamsGetString(params, nparams,
                                    VIR_MIGRATE_PARAM_DEST_NAME, NULL) <= 0 &&
            // if user does not set domain name, set domain name in migration parameter from source->def->name
            virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_DEST_NAME,
                                        vm->def->name) < 0) {
            ddomain = NULL;
        } else {
            // release vm lock as rpc call
            qemuDomainObjEnterRemote(vm);
            // after Finish3 returns the remote libvirtd exits the migration process migration job is gone!!!
            ddomain = dconn->driver->domainMigrateFinish3Params
                (dconn, params, nparams, cookiein, cookieinlen,
                 &cookieout, &cookieoutlen, destflags, cancelled);
            // get vm lock again
            if (qemuDomainObjExitRemote(vm, !offline) < 0)
                goto cleanup;
        }
    } else {
        dname = dname ? dname : vm->def->name;
        qemuDomainObjEnterRemote(vm);
        // notify remote libvirt that migration finished
        ddomain = dconn->driver->domainMigrateFinish3
            (dconn, dname, cookiein, cookieinlen, &cookieout, &cookieoutlen,
             dconnuri, uri, destflags, cancelled);
        if (qemuDomainObjExitRemote(vm, !offline) < 0)
            goto cleanup;
    }

    // cancelled is true when Perform error(error when do migration copy)!!!
    if (cancelled) {
        if (ddomain) {
            VIR_ERROR(_("finish step ignored that migration was cancelled"));
        } else {
            /* If Finish reported a useful error, use it instead of the
             * original "migration unexpectedly failed" error.
             *
             * This is ugly but we can't do better with the APIs we have. We
             * only replace the error if Finish was called with cancelled == 1
             * and reported a real error (old libvirt would report an error
             * from RPC instead of MIGRATE_FINISH_OK), which only happens when
             * the domain died on destination. To further reduce a possibility
             * of false positives we also check that Perform returned
             * VIR_ERR_OPERATION_FAILED.
             */
            if (orig_err &&
                orig_err->domain == VIR_FROM_QEMU &&
                orig_err->code == VIR_ERR_OPERATION_FAILED) {
                virErrorPtr err = virGetLastError();
                if (err &&
                    err->domain == VIR_FROM_QEMU &&
                    err->code != VIR_ERR_MIGRATE_FINISH_OK) {
                    virFreeError(orig_err);
                    orig_err = NULL;
                }
            }
        }
    }

    /* If ddomain is NULL, then we were unable to start
     * the guest on the target, and must restart on the
     * source. There is a small chance that the ddomain
     * is NULL due to an RPC failure, in which case
     * ddomain could in fact be running on the dest.
     * The lock manager plugins should take care of
     * safety in this scenario.
     *
     *
     * now cancelled == return value of Finish3(which check if guest starts ok after migration done)
     */
    cancelled = ddomain == NULL;

    /* If finish3 set an error, and we don't have an earlier
     * one we need to preserve it in case confirm3 overwrites
     */
    if (!orig_err)
        orig_err = virSaveLastError();

    /*
     * If cancelled, then src VM will be restarted(may be in paused state due to post-copy error), else
     * it will be killed
     */
    VIR_DEBUG("Confirm3 %p cancelled=%d vm=%p", sconn, cancelled, vm);
    VIR_FREE(cookiein);
    // cookiein now is cookie return by Finish3
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;

    // confirm means: update jobinfo stats got from dst libvirtd if have and kill vm if migration is ok, or resume it if fails
    ret = qemuMigrationSrcConfirmPhase(driver, vm,
                                       cookiein, cookieinlen,
                                       flags, cancelled);
    /* If Confirm3 returns -1, there's nothing more we can do
     * ======================================================
     * but fortunately worst case is that there is a
     * domain left in 'paused' state on source.
     * ======================================================
     */
    if (ret < 0)
        VIR_WARN("Guest %s probably left in 'paused' state on source",
                 vm->def->name);

 cleanup:
    if (ddomain) {
        virObjectUnref(ddomain);
        ret = 0;
    } else {
        ret = -1;
    }

    virObjectUnref(st);

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE(uri_out);
    VIR_FREE(cookiein);
    VIR_FREE(cookieout);
    virTypedParamsFree(params, nparams);
    return ret;
}


static void
qemuMigrationSrcConnectionClosed(virConnectPtr conn,
                                 int reason,
                                 void *opaque)
{
    virDomainObjPtr vm = opaque;

    VIR_DEBUG("conn=%p, reason=%d, vm=%s", conn, reason, vm->def->name);
    // wakup any operation that blocks on vm condition
    virDomainObjBroadcast(vm);
}


static int virConnectCredType[] = {
    VIR_CRED_AUTHNAME,
    VIR_CRED_PASSPHRASE,
};


static virConnectAuth virConnectAuthConfig = {
    .credtype = virConnectCredType,
    .ncredtype = ARRAY_CARDINALITY(virConnectCredType),
};


static int
qemuMigrationSrcPerformPeer2Peer(virQEMUDriverPtr driver,
                                 virConnectPtr sconn,
                                 virDomainObjPtr vm,
                                 const char *xmlin,
                                 const char *persist_xml,
                                 const char *dconnuri,
                                 const char *uri,
                                 const char *graphicsuri,
                                 const char *listenAddress,
                                 size_t nmigrate_disks,
                                 const char **migrate_disks,
                                 int nbdPort,
                                 qemuMigrationParamsPtr migParams,
                                 unsigned long flags,
                                 const char *dname,
                                 unsigned long resource,
                                 bool *v3proto)
{
    // this is used by p2p and tunneled case
    int ret = -1;
    virConnectPtr dconn = NULL;
    bool p2p;
    virErrorPtr orig_err = NULL;
    bool offline = !!(flags & VIR_MIGRATE_OFFLINE);
    bool dstOffline = false;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    bool useParams;

    VIR_DEBUG("driver=%p, sconn=%p, vm=%p, xmlin=%s, dconnuri=%s, uri=%s, "
              "graphicsuri=%s, listenAddress=%s, nmigrate_disks=%zu, "
              "migrate_disks=%p, nbdPort=%d, flags=0x%lx, dname=%s, "
              "resource=%lu",
              driver, sconn, vm, NULLSTR(xmlin), NULLSTR(dconnuri),
              NULLSTR(uri), NULLSTR(graphicsuri), NULLSTR(listenAddress),
              nmigrate_disks, migrate_disks, nbdPort, flags, NULLSTR(dname),
              resource);

    if (flags & VIR_MIGRATE_TUNNELLED && uri) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("migration URI is not supported by tunnelled "
                         "migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_TUNNELLED && listenAddress) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("listen address is not supported by tunnelled "
                         "migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_TUNNELLED && nbdPort) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("disk port address is not supported by tunnelled "
                         "migration"));
        goto cleanup;
    }

    /* the order of operations is important here; we make sure the
     * destination side is completely setup before we touch the source
     */

    // enter remote: release vm lock!!! when connection with remote libvirtd
    qemuDomainObjEnterRemote(vm);
    // connect with remote libvirtd with dconnuri
    dconn = virConnectOpenAuth(dconnuri, &virConnectAuthConfig, 0);

    // get vm lock again after connection setup or fail
    if (qemuDomainObjExitRemote(vm, !offline) < 0)
        goto cleanup;

    if (dconn == NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to connect to remote libvirt URI %s: %s"),
                       dconnuri, virGetLastErrorMessage());
        virObjectUnref(cfg);
        return -1;
    }

    // setup keepalive with remote libvirtd
    if (virConnectSetKeepAlive(dconn, cfg->keepAliveInterval,
                               cfg->keepAliveCount) < 0)
        goto cleanup;

    // callback when connection with remote libivirtd closed
    // callback does: wakeup anyone who block on vm condition
    //
    // TODO: should we relase vm lock here as it's rpc call?
    // NO, as vm is used in register close callback???
    if (virConnectRegisterCloseCallback(dconn, qemuMigrationSrcConnectionClosed,
                                        vm, NULL) < 0) {
        goto cleanup;
    }

    // release vm lock when doing network operation(connect, rpc call)
    qemuDomainObjEnterRemote(vm);
    // check if remote libvirtd supports p2p by rpc call
    p2p = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                   VIR_DRV_FEATURE_MIGRATION_P2P);
        /* v3proto reflects whether the caller used Perform3, but with
         * p2p migrate, regardless of whether Perform2 or Perform3
         * were used, we decide protocol based on what target supports
         */

    // check if remote libvirtd supports v3 migration by rpc call
    *v3proto = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                        VIR_DRV_FEATURE_MIGRATION_V3);
    // check if remote libvirtd supports v3 migration extension by rpc call
    useParams = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                         VIR_DRV_FEATURE_MIGRATION_PARAMS);
    if (offline)
        // check if remote libvirtd supports offline
        dstOffline = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                              VIR_DRV_FEATURE_MIGRATION_OFFLINE);

    // get vm lock again
    if (qemuDomainObjExitRemote(vm, !offline) < 0)
        goto cleanup;

    if (!p2p) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Destination libvirt does not support peer-to-peer migration protocol"));
        goto cleanup;
    }

    /* Only xmlin, dname, uri, and bandwidth parameters can be used with
     * old-style APIs. */
    if (!useParams && (graphicsuri || listenAddress || nmigrate_disks)) {
        // new parameters set but remote libvirtd does not support v3 extension!!!
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Migration APIs with extensible parameters are not "
                         "supported but extended parameters were passed"));
        goto cleanup;
    }

    if (offline && !dstOffline) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("offline migration is not supported by "
                         "the destination host"));
        goto cleanup;
    }

    /* Change protection is only required on the source side (us), and
     * only for v3 migration when begin and perform are separate jobs.
     * But peer-2-peer is already a single job, and we still want to
     * talk to older destinations that would reject the flag.
     * Therefore it is safe to clear the bit here.  */
    flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;

    if (*v3proto) {
        // use migration v3 protocol as remote libvirtd supports it
        ret = qemuMigrationSrcPerformPeer2Peer3(driver, sconn, dconn, dconnuri, vm, xmlin,
                                                persist_xml, dname, uri, graphicsuri,
                                                listenAddress, nmigrate_disks, migrate_disks,
                                                nbdPort, migParams, resource,
                                                useParams, flags);
    } else {
        ret = qemuMigrationSrcPerformPeer2Peer2(driver, sconn, dconn, vm,
                                                dconnuri, flags, dname, resource,
                                                migParams);
    }

 cleanup:
    orig_err = virSaveLastError();
    // relase vm lock, we do unregister closecallback which is rpc call
    qemuDomainObjEnterRemote(vm);
    virConnectUnregisterCloseCallback(dconn, qemuMigrationSrcConnectionClosed);
    virObjectUnref(dconn);
    // get vm lock again
    ignore_value(qemuDomainObjExitRemote(vm, false));
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    virObjectUnref(cfg);
    return ret;
}


/*
 * This implements perform part of the migration protocol when migration job
 * does not need to be active across several APIs, i.e., peer2peer migration or
 * perform phase of v2 non-peer2peer migration.
 */
static int
qemuMigrationSrcPerformJob(virQEMUDriverPtr driver,
                           virConnectPtr conn,
                           virDomainObjPtr vm,
                           const char *xmlin,
                           const char *persist_xml,
                           const char *dconnuri,
                           const char *uri,
                           const char *graphicsuri,
                           const char *listenAddress,
                           size_t nmigrate_disks,
                           const char **migrate_disks,
                           int nbdPort,
                           qemuMigrationParamsPtr migParams,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           unsigned long flags,
                           const char *dname,
                           unsigned long resource,
                           bool v3proto)
{
    virObjectEventPtr event = NULL;
    int ret = -1;
    virErrorPtr orig_err = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;

    // source set async migration job
    if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                              flags) < 0)
        goto cleanup;

    // live migration but vm is not active
    if (!(flags & VIR_MIGRATE_OFFLINE) && virDomainObjCheckActive(vm) < 0)
        goto endjob;

    // not allowed to migrate cases
    if (!qemuMigrationSrcIsAllowed(driver, vm, true, flags))
        goto endjob;

    // migrate local disk without unsafe or offline flags set
    // or disk with cache!=none both are unsafe!!!
    if (!(flags & (VIR_MIGRATE_UNSAFE | VIR_MIGRATE_OFFLINE)) &&
        !qemuMigrationSrcIsSafe(vm->def, nmigrate_disks, migrate_disks, flags))
        goto endjob;

    // save the vm state before migration used for restore vm for migration error that cause vm paused.
    qemuMigrationSrcStoreDomainState(vm);

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        ret = qemuMigrationSrcPerformPeer2Peer(driver, conn, vm, xmlin, persist_xml,
                                               dconnuri, uri, graphicsuri, listenAddress,
                                               nmigrate_disks, migrate_disks, nbdPort,
                                               migParams, flags, dname, resource,
                                               &v3proto);
    } else {
        qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM2);
        ret = qemuMigrationSrcPerformNative(driver, vm, persist_xml, uri, cookiein, cookieinlen,
                                            cookieout, cookieoutlen,
                                            flags, resource, NULL, NULL, 0, NULL,
                                            migParams);
    }
    if (ret < 0)
        goto endjob;

    /*
     * In v3 protocol, the source VM is not killed off until the
     * confirm step.
     */
    if (!v3proto) {
        // if it's v3, we already kill the vm at confirm step above
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_MIGRATED,
                        QEMU_ASYNC_JOB_MIGRATION_OUT,
                        VIR_QEMU_PROCESS_STOP_MIGRATED);
        virDomainAuditStop(vm, "migrated");
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    }

 endjob:
    if (ret < 0)
        orig_err = virSaveLastError();

    /* v2 proto has no confirm phase so we need to reset migration parameters
     * here
     */
    if (!v3proto && ret < 0)
        // if v3 and error happens(vm is still running), reset migration parameters
        // by sending QMP command(MIGRATION_OP is allowed) even async migration job is not finished now
        qemuMigrationParamsReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                 priv->job.migParams, priv->job.apiFlags);

    if (qemuMigrationSrcRestoreDomainState(driver, vm)) {
        // restore vm if migration error happens
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    }

    // migration finishes(confirmed), error or ok, finish async job, set it to NONE
    // so other operation blocks on it can continue
    qemuMigrationJobFinish(driver, vm);
    if (!virDomainObjIsActive(vm) && ret == 0) {
        // successfully migration and vm is not active now
        // if undefined_source is set, remove config of this vm from /etc
        if (flags & VIR_MIGRATE_UNDEFINE_SOURCE) {
            virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm);
            vm->persistent = 0;
        }
        qemuDomainRemoveInactiveJob(driver, vm);
    }

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}

/*
 * This implements perform phase of v3 migration protocol.
 */
static int
qemuMigrationSrcPerformPhase(virQEMUDriverPtr driver,
                             virConnectPtr conn,
                             virDomainObjPtr vm,
                             const char *persist_xml,
                             const char *uri,
                             const char *graphicsuri,
                             size_t nmigrate_disks,
                             const char **migrate_disks,
                             qemuMigrationParamsPtr migParams,
                             const char *cookiein,
                             int cookieinlen,
                             char **cookieout,
                             int *cookieoutlen,
                             unsigned long flags,
                             unsigned long resource)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virObjectEventPtr event = NULL;
    int ret = -1;

    /* If we didn't start the job in the begin phase, start it now. */
    if (!(flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                  flags) < 0)
            goto cleanup;
    } else if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_OUT)) {
        goto cleanup;
    }

    qemuMigrationJobStartPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM3);
    virCloseCallbacksUnset(driver->closeCallbacks, vm,
                           qemuMigrationSrcCleanup);

    ret = qemuMigrationSrcPerformNative(driver, vm, persist_xml, uri, cookiein, cookieinlen,
                                        cookieout, cookieoutlen,
                                        flags, resource, NULL, graphicsuri,
                                        nmigrate_disks, migrate_disks, migParams);

    if (ret < 0) {
        if (qemuMigrationSrcRestoreDomainState(driver, vm)) {
            event = virDomainEventLifecycleNewFromObj(vm,
                                                      VIR_DOMAIN_EVENT_RESUMED,
                                                      VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
        }
        goto endjob;
    }

    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM3_DONE);

    if (virCloseCallbacksSet(driver->closeCallbacks, vm, conn,
                             qemuMigrationSrcCleanup) < 0)
        goto endjob;

 endjob:
    if (ret < 0) {
        qemuMigrationParamsReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                 priv->job.migParams, priv->job.apiFlags);
        qemuMigrationJobFinish(driver, vm);
    } else {
        qemuMigrationJobContinue(vm);
    }

    if (!virDomainObjIsActive(vm))
        qemuDomainRemoveInactiveJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    return ret;
}

// This is a common operation called by Perform, Perform2, Perform3
// so that some parameters are NULL for Perform and Perform2, while not NULL if set by Perform3
int
qemuMigrationSrcPerform(virQEMUDriverPtr driver,
                        virConnectPtr conn,
                        virDomainObjPtr vm,
                        const char *xmlin,
                        const char *persist_xml,
                        const char *dconnuri,
                        const char *uri,
                        const char *graphicsuri,
                        const char *listenAddress,
                        size_t nmigrate_disks,
                        const char **migrate_disks,
                        int nbdPort,
                        qemuMigrationParamsPtr migParams,
                        const char *cookiein,
                        int cookieinlen,
                        char **cookieout,
                        int *cookieoutlen,
                        unsigned long flags,
                        const char *dname,
                        unsigned long resource,
                        bool v3proto)
{
    VIR_DEBUG("driver=%p, conn=%p, vm=%p, xmlin=%s, dconnuri=%s, "
              "uri=%s, graphicsuri=%s, listenAddress=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p, nbdPort=%d, "
              "cookiein=%s, cookieinlen=%d, cookieout=%p, cookieoutlen=%p, "
              "flags=0x%lx, dname=%s, resource=%lu, v3proto=%d",
              driver, conn, vm, NULLSTR(xmlin), NULLSTR(dconnuri),
              NULLSTR(uri), NULLSTR(graphicsuri), NULLSTR(listenAddress),
              nmigrate_disks, migrate_disks, nbdPort,
              NULLSTR(cookiein), cookieinlen, cookieout, cookieoutlen,
              flags, NULLSTR(dname), resource, v3proto);

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        if (cookieinlen) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("received unexpected cookie with P2P migration"));
            return -1;
        }

        return qemuMigrationSrcPerformJob(driver, conn, vm, xmlin, persist_xml, dconnuri, uri,
                                          graphicsuri, listenAddress,
                                          nmigrate_disks, migrate_disks, nbdPort,
                                          migParams,
                                          cookiein, cookieinlen,
                                          cookieout, cookieoutlen,
                                          flags, dname, resource, v3proto);
    } else {
        if (dconnuri) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Unexpected dconnuri parameter with non-peer2peer migration"));
            return -1;
        }

        if (v3proto) {
            // v3 not support new xml for migration vm at remote host
            return qemuMigrationSrcPerformPhase(driver, conn, vm, persist_xml, uri,
                                                graphicsuri,
                                                nmigrate_disks, migrate_disks,
                                                migParams,
                                                cookiein, cookieinlen,
                                                cookieout, cookieoutlen,
                                                flags, resource);
        } else {
            return qemuMigrationSrcPerformJob(driver, conn, vm, xmlin, persist_xml, NULL,
                                              uri, graphicsuri, listenAddress,
                                              nmigrate_disks, migrate_disks, nbdPort,
                                              migParams,
                                              cookiein, cookieinlen,
                                              cookieout, cookieoutlen, flags,
                                              dname, resource, v3proto);
        }
    }
}

static int
qemuMigrationDstVPAssociatePortProfiles(virDomainDefPtr def)
{
    size_t i;
    int last_good_net = -1;
    virDomainNetDefPtr net;

    for (i = 0; i < def->nnets; i++) {
        net = def->nets[i];
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
            if (virNetDevVPortProfileAssociate(net->ifname,
                                               virDomainNetGetActualVirtPortProfile(net),
                                               &net->mac,
                                               virDomainNetGetActualDirectDev(net),
                                               -1,
                                               def->uuid,
                                               VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_FINISH,
                                               false) < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Port profile Associate failed for %s"),
                               net->ifname);
                goto err_exit;
            }
            last_good_net = i;
            VIR_DEBUG("Port profile Associate succeeded for %s", net->ifname);

            if (virNetDevMacVLanVPortProfileRegisterCallback(net->ifname, &net->mac,
                                                             virDomainNetGetActualDirectDev(net), def->uuid,
                                                             virDomainNetGetActualVirtPortProfile(net),
                                                             VIR_NETDEV_VPORT_PROFILE_OP_CREATE))
                goto err_exit;
        }
    }

    return 0;

 err_exit:
    for (i = 0; last_good_net != -1 && i <= last_good_net; i++) {
        net = def->nets[i];
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
            ignore_value(virNetDevVPortProfileDisassociate(net->ifname,
                                                           virDomainNetGetActualVirtPortProfile(net),
                                                           &net->mac,
                                                           virDomainNetGetActualDirectDev(net),
                                                           -1,
                                                           VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_FINISH));
        }
    }
    return -1;
}


static int
qemuMigrationDstPersist(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        qemuMigrationCookiePtr mig,
                        bool ignoreSaveError)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virCapsPtr caps = NULL;
    virDomainDefPtr vmdef;
    virDomainDefPtr oldDef = NULL;
    unsigned int oldPersist = vm->persistent;
    virObjectEventPtr event;
    int ret = -1;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    vm->persistent = 1;
    // oldDef is the def when Prepare3
    oldDef = vm->newDef;
    // def from cookie use it and free oldDef
    vm->newDef = qemuMigrationCookieGetPersistent(mig);

    if (!(vmdef = virDomainObjGetPersistentDef(caps, driver->xmlopt, vm)))
        goto error;

    if (virDomainSaveConfig(cfg->configDir, driver->caps, vmdef) < 0 &&
        !ignoreSaveError)
        goto error;

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_DEFINED,
                                              oldPersist ?
                                              VIR_DOMAIN_EVENT_DEFINED_UPDATED :
                                              VIR_DOMAIN_EVENT_DEFINED_ADDED);
    virObjectEventStateQueue(driver->domainEventState, event);

    ret = 0;

 cleanup:
    virDomainDefFree(oldDef);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;

 error:
    virDomainDefFree(vm->newDef);
    vm->persistent = oldPersist;
    vm->newDef = oldDef;
    oldDef = NULL;
    goto cleanup;
}


// as this can be called by V2 and V3, v3proto indicate who calls me
virDomainPtr
qemuMigrationDstFinish(virQEMUDriverPtr driver,
                       virConnectPtr dconn,
                       virDomainObjPtr vm,
                       const char *cookiein,
                       int cookieinlen,
                       char **cookieout,
                       int *cookieoutlen,
                       unsigned long flags,
                       int retcode,
                       bool v3proto)
{
    virDomainPtr dom = NULL;
    qemuMigrationCookiePtr mig = NULL;
    virErrorPtr orig_err = NULL;
    int cookie_flags = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    unsigned short port;
    unsigned long long timeReceived = 0;
    virObjectEventPtr event;
    qemuDomainJobInfoPtr jobInfo = NULL;
    bool inPostCopy = false;
    bool doKill = true;

    VIR_DEBUG("driver=%p, dconn=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=0x%lx, retcode=%d",
              driver, dconn, vm, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, retcode);

    port = priv->migrationPort;
    priv->migrationPort = 0;

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_IN)) {
        qemuMigrationDstErrorReport(driver, vm->def->name);
        goto cleanup;
    }

    ignore_value(virTimeMillisNow(&timeReceived));

    qemuMigrationJobStartPhase(driver, vm,
                               v3proto ? QEMU_MIGRATION_PHASE_FINISH3
                                       : QEMU_MIGRATION_PHASE_FINISH2);

    // remove cleanup for migration
    // vm cleanup runs when stop vm process
    // this runs at dst side
    qemuDomainCleanupRemove(vm, qemuMigrationDstPrepareCleanup);
    VIR_FREE(priv->job.completed);

    // cookie_flags indicates what cookie I will collect and send it back to source
    cookie_flags = QEMU_MIGRATION_COOKIE_NETWORK |
                   QEMU_MIGRATION_COOKIE_STATS |
                   QEMU_MIGRATION_COOKIE_NBD;
    /* Some older versions of libvirt always send persistent XML in the cookie
     * even though VIR_MIGRATE_PERSIST_DEST was not used. */
    cookie_flags |= QEMU_MIGRATION_COOKIE_PERSISTENT;

    if (!(mig = qemuMigrationEatCookie(driver, vm, cookiein,
                                       cookieinlen, cookie_flags)))
        goto endjob;

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (retcode == 0 &&
            qemuMigrationDstPersist(driver, vm, mig, false) == 0)
            dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, -1);
        goto endjob;
    }

    // check Perform3 return value
    if (retcode != 0) {
        // retcode is return value of Perform3 passed by source when do FINISH3 call

        /* Check for a possible error on the monitor in case Finish was called
         * earlier than monitor EOF handler got a chance to process the error
         */
        qemuDomainCheckMonitor(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN);
        goto endjob;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        qemuMigrationDstErrorReport(driver, vm->def->name);
        goto endjob;
    }

    if (qemuMigrationDstVPAssociatePortProfiles(vm->def) < 0)
        goto endjob;

    if (mig->network && qemuMigrationDstOPDRelocate(driver, vm, mig) < 0)
        VIR_WARN("unable to provide network data for relocation");

    // stop ndb server as Perform3 finished
    if (qemuMigrationDstStopNBDServer(driver, vm, mig) < 0)
        goto endjob;

    // why refresh channel state
    // NOTE: as connect agent will use the the channel state!!!
    if (qemuRefreshVirtioChannelState(driver, vm,
                                      QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        goto endjob;

    if (qemuConnectAgent(driver, vm) < 0)
        goto endjob;

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        // persist vm, write conf to /etc, conf is from cookie!!!
        if (qemuMigrationDstPersist(driver, vm, mig, !v3proto) < 0) {
            /* Hmpf.  Migration was successful, but making it persistent
             * was not.  If we report successful, then when this domain
             * shuts down, management tools are in for a surprise.  On the
             * other hand, if we report failure, then the management tools
             * might try to restart the domain on the source side, even
             * though the domain is actually running on the destination.
             * Pretend success and hope that this is a rare situation and
             * management tools are smart.
             *
             * However, in v3 protocol, the source VM is still available
             * to restart during confirm() step, so we kill it off now.
             */
            if (v3proto)
                goto endjob;
        }
    }

    /* We need to wait for QEMU to process all data sent by the source
     * before starting guest CPUs.
     *
     * wait for completion at dst host as well.
     * migration completed when async job status comes into completed
     * job status changed based on QMP event reported by local qemu process or migration ops
     * qemuMigrationDstWaitForCompletion returns when job status in:
     * Paused, PostCopy, Completed.
     *
     * even source finish migration(completed), dst here should wait for completion as well
     */
    if (qemuMigrationDstWaitForCompletion(driver, vm,
                                          QEMU_ASYNC_JOB_MIGRATION_IN,
                                          !!(flags & VIR_MIGRATE_POSTCOPY)) < 0) {
        /* There's not much we can do for v2 protocol since the
         * original domain on the source host is already gone.
         */
        if (v3proto)
            goto endjob;
    }

    /* Now that the state data was transferred we can refresh the actual state
     * of the devices(devices, memory, disk)
     */
    if (qemuProcessRefreshState(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN) < 0) {
        /* Similarly to the case above v2 protocol will not be able to recover
         * from this. Let's ignore this and perhaps stuff will not break. */
        if (v3proto)
            goto endjob;
    }

    // wait returns due to goes in post-copy status
    if (priv->job.current->status == QEMU_DOMAIN_JOB_STATUS_POSTCOPY)
        inPostCopy = true;

    if (!(flags & VIR_MIGRATE_PAUSED)) {
        // if source is paued, after migration, it's paused as well, we does not start vm as well!!!
        // but source vm is shutoff if migration is ok.
        //
        /* run 'cont' on the destination, which allows migration on qemu
         * >= 0.10.6 to work properly.  This isn't strictly necessary on
         * older qemu's, but it also doesn't hurt anything there
         *
         *
         * start vm(make it run) after migrated or switch into postcopy
         * libvirtd issues start vm, not qemu itself
         */
        if (qemuProcessStartCPUs(driver, vm,
                                 inPostCopy ? VIR_DOMAIN_RUNNING_POSTCOPY
                                            : VIR_DOMAIN_RUNNING_MIGRATED,
                                 QEMU_ASYNC_JOB_MIGRATION_IN) < 0) {
            if (virGetLastErrorCode() == VIR_ERR_OK)
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("resume operation failed"));
            /* Need to save the current error, in case shutting
             * down the process overwrites it
             */
            orig_err = virSaveLastError();

            /*
             * In v3 protocol, the source VM is still available to
             * restart during confirm() step, so we kill it off
             * now.
             * In v2 protocol, the source is dead, so we leave
             * target in paused state, in case admin can fix
             * things up.
             */
            if (v3proto)
                goto endjob;
        }

        if (inPostCopy) {
            doKill = false;
            event = virDomainEventLifecycleNewFromObj(vm,
                                        VIR_DOMAIN_EVENT_RESUMED,
                                        VIR_DOMAIN_EVENT_RESUMED_POSTCOPY);
            virObjectEventStateQueue(driver->domainEventState, event);
        }
    }

    if (mig->jobInfo) {
        jobInfo = mig->jobInfo;
        mig->jobInfo = NULL;

        // update jobinfo(stats) when migration finished or in post-copy
        if (jobInfo->sent && timeReceived) {
            jobInfo->timeDelta = timeReceived - jobInfo->sent;
            jobInfo->received = timeReceived;
            jobInfo->timeDeltaSet = true;
        }
        // update migraion stats at dst side
        qemuDomainJobInfoUpdateTime(jobInfo);
        qemuDomainJobInfoUpdateDowntime(jobInfo);
    }

    if (inPostCopy) {
        // if in post copy, wait for migration completed event!!!
        if (qemuMigrationDstWaitForCompletion(driver, vm,
                                              QEMU_ASYNC_JOB_MIGRATION_IN,
                                              false) < 0) {
            goto endjob;
        }

        if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
            virDomainObjSetState(vm,
                                 VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_MIGRATED);
        }
    }

    dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, vm->def->id);

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_RESUMED,
                                              VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    virObjectEventStateQueue(driver->domainEventState, event);

    // paused that means source vm is paused before migration
    // after migration, vm at dst is still paused!!!
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    // pause is active as well!!!
    if (virDomainObjIsActive(vm) &&
        virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        VIR_WARN("Failed to save status on vm %s", vm->def->name);

    /* Guest is successfully running, so cancel previous auto destroy */
    qemuProcessAutoDestroyRemove(driver, vm);

 endjob:
    if (!dom &&
        !(flags & VIR_MIGRATE_OFFLINE) &&
        virDomainObjIsActive(vm)) {
        if (doKill) {
            qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                            QEMU_ASYNC_JOB_MIGRATION_IN,
                            VIR_QEMU_PROCESS_STOP_MIGRATED);
            virDomainAuditStop(vm, "failed");
            event = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_STOPPED,
                                VIR_DOMAIN_EVENT_STOPPED_FAILED);
            virObjectEventStateQueue(driver->domainEventState, event);
        } else {
            qemuMigrationAnyPostcopyFailed(driver, vm);
        }
    }

    if (dom) {
        if (jobInfo) {
            // save jobinfostats) to job.completed
            VIR_STEAL_PTR(priv->job.completed, jobInfo);
            priv->job.completed->status = QEMU_DOMAIN_JOB_STATUS_COMPLETED;
            priv->job.completed->statsType = QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION;
        }

        // generate cookie with stats from dst side when src calls FINISH
        /*
         * </qemu-migration>
         *   <name>vm100</name>
         *   <uuid>e8b6545e-3fef-4a98-b222-18b2eed9f2f1</uuid>
         *   <hostname>dev</hostname>
         *   <hostuuid>1c66e1c0-e1c1-4ef8-986b-956d299a11cd</hostuuid>
         *   <nbd>
         *     <disk target='vda' capacity='8589934592'/>
         *     <disk target='vdc' capacity='358400'/>
         *   </nbd>
         *   <statistics>
         *     <started>1661932320325</started>
         *     <stopped>1661933165088</stopped>
         *     <sent>1661933165173</sent>
         *     <time_elapsed>844848</time_elapsed>
         *     <downtime>85</downtime>
         *     <setup_time>58</setup_time>
         *     <memory_total>1615929344</memory_total>
         *     <memory_processed>310983868</memory_processed>
         *     <memory_remaining>0</memory_remaining>
         *     <memory_bps>13542105</memory_bps>
         *     <memory_constant>321599</memory_constant>
         *     <memory_normal>75070</memory_normal>
         *     <memory_normal_bytes>307486720</memory_normal_bytes>
         *     <memory_dirty_rate>0</memory_dirty_rate>
         *     <memory_iteration>5</memory_iteration>
         *     <memory_page_size>4096</memory_page_size>
         *     <disk_total>0</disk_total>
         *     <disk_processed>0</disk_processed>
         *     <disk_remaining>0</disk_remaining>
         *     <disk_bps>0</disk_bps>
         *     <auto_converge_throttle>0</auto_converge_throttle>
         *   </statistics>
         * </qemu-migration>
         *
         * create FINISH3 cookie
         */
        if (qemuMigrationBakeCookie(mig, driver, vm,
                                    QEMU_MIGRATION_DESTINATION,
                                    cookieout, cookieoutlen,
                                    QEMU_MIGRATION_COOKIE_STATS) < 0)
            VIR_WARN("Unable to encode migration cookie");

        /* Remove completed stats for post-copy, everything but timing fields
         * is obsolete anyway.
         */
        if (inPostCopy)
            VIR_FREE(priv->job.completed);
    }

    // reset migration parameter from priv->job.migParam which stores the orginal setting.
    qemuMigrationParamsReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                             priv->job.migParams, priv->job.apiFlags);

    // migration finished, end async job, so that other jobs blocks on async can continue to run
    qemuMigrationJobFinish(driver, vm);
    if (!virDomainObjIsActive(vm))
        qemuDomainRemoveInactiveJob(driver, vm);

 cleanup:
    VIR_FREE(jobInfo);
    virPortAllocatorRelease(port);
    if (priv->mon)
        qemuMonitorSetDomainLog(priv->mon, NULL, NULL, NULL);
    VIR_FREE(priv->origname);
    virDomainObjEndAPI(&vm);
    qemuMigrationCookieFree(mig);
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    virObjectUnref(cfg);

    /* Set a special error if Finish is expected to return NULL as a result of
     * successful call with retcode != 0
     */
    if (retcode != 0 && !dom && virGetLastErrorCode() == VIR_ERR_OK)
        virReportError(VIR_ERR_MIGRATE_FINISH_OK, NULL);
    return dom;
}


/* Helper function called while vm is active.  */
int
qemuMigrationSrcToFile(virQEMUDriverPtr driver, virDomainObjPtr vm,
                       int fd,
                       const char *compressor,
                       qemuDomainAsyncJob asyncJob)
{
    // NOTE: when dump memory to file, vm is active but vcpu in Paused state!!!
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;
    int ret = -1;
    virCommandPtr cmd = NULL;
    int pipeFD[2] = { -1, -1 };
    unsigned long saveMigBandwidth = priv->migMaxBandwidth;
    char *errbuf = NULL;
    virErrorPtr orig_err = NULL;

    /* Increase migration bandwidth to unlimited since target is a file.
     * Failure to change migration speed is not fatal. */
    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
        // QMP "migrate_set_speed" to set migrate speed
        qemuMonitorSetMigrationSpeed(priv->mon,
                                     QEMU_DOMAIN_MIG_BANDWIDTH_MAX);
        priv->migMaxBandwidth = QEMU_DOMAIN_MIG_BANDWIDTH_MAX;
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            return -1;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        /* nothing to tear down */
        return -1;
    }

    if (compressor && pipe(pipeFD) < 0) {
        // pipd is needed only compression is enabled
        virReportSystemError(errno, "%s",
                             _("Failed to create pipe for migration"));
        return -1;
    }

    /* All right! We can use fd migration, which means that qemu
     * doesn't have to open() the file, so while we still have to
     * grant SELinux access, we can do it on fd and avoid cleanup
     * later, as well as skip futzing with cgroup.  */
    if (qemuSecuritySetImageFDLabel(driver->securityManager, vm->def,
                                    compressor ? pipeFD[1] : fd) < 0)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    if (!compressor) {
        rc = qemuMonitorMigrateToFd(priv->mon,
                                    QEMU_MONITOR_MIGRATE_BACKGROUND,
                                    fd);
    } else {
        const char *prog = compressor;
        const char *args[] = {
            prog,
            "-c",
            NULL
        };

        cmd = virCommandNewArgs(args);
        virCommandSetInputFD(cmd, pipeFD[0]);
        virCommandSetOutputFD(cmd, &fd);
        virCommandSetErrorBuffer(cmd, &errbuf);
        virCommandDoAsyncIO(cmd);
        if (virSetCloseExec(pipeFD[1]) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to set cloexec flag"));
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            goto cleanup;
        }
        if (virCommandRunAsync(cmd, NULL) < 0) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            goto cleanup;
        }
        rc = qemuMonitorMigrateToFd(priv->mon,
                                    QEMU_MONITOR_MIGRATE_BACKGROUND,
                                    pipeFD[1]);
        if (VIR_CLOSE(pipeFD[0]) < 0 ||
            VIR_CLOSE(pipeFD[1]) < 0)
            VIR_WARN("failed to close intermediate pipe");
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;
    if (rc < 0)
        goto cleanup;

    rc = qemuMigrationSrcWaitForCompletion(driver, vm, asyncJob, NULL, 0);

    if (rc < 0) {
        if (rc == -2) {
            orig_err = virSaveLastError();
            virCommandAbort(cmd);
            if (virDomainObjIsActive(vm) &&
                qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
                qemuMonitorMigrateCancel(priv->mon);
                ignore_value(qemuDomainObjExitMonitor(driver, vm));
            }
        }
        goto cleanup;
    }

    if (cmd && virCommandWait(cmd, NULL) < 0)
        goto cleanup;

    qemuDomainEventEmitJobCompleted(driver, vm);
    ret = 0;

 cleanup:
    if (ret < 0 && !orig_err)
        orig_err = virSaveLastError();

    /* Restore max migration bandwidth */
    if (virDomainObjIsActive(vm) &&
        qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
        qemuMonitorSetMigrationSpeed(priv->mon, saveMigBandwidth);
        priv->migMaxBandwidth = saveMigBandwidth;
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
    }

    VIR_FORCE_CLOSE(pipeFD[0]);
    VIR_FORCE_CLOSE(pipeFD[1]);
    if (cmd) {
        VIR_DEBUG("Compression binary stderr: %s", NULLSTR(errbuf));
        VIR_FREE(errbuf);
        virCommandFree(cmd);
    }

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

    return ret;
}


int
qemuMigrationSrcCancel(virQEMUDriverPtr driver,
                       virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virHashTablePtr blockJobs = NULL;
    bool storage = false;
    size_t i;
    int ret = -1;

    VIR_DEBUG("Canceling unfinished outgoing migration of domain %s",
              vm->def->name);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        if (QEMU_DOMAIN_DISK_PRIVATE(disk)->migrating) {
            qemuBlockJobSyncBegin(disk);
            storage = true;
        }
    }

    qemuDomainObjEnterMonitor(driver, vm);

    // cancel migration by sending QMP 'migrate_cancel`
    ignore_value(qemuMonitorMigrateCancel(priv->mon));
    if (storage)
        blockJobs = qemuMonitorGetAllBlockJobInfo(priv->mon);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || (storage && !blockJobs))
        goto endsyncjob;

    if (!storage) {
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!diskPriv->migrating)
            continue;

        if (virHashLookup(blockJobs, disk->info.alias)) {
            VIR_DEBUG("Drive mirror on disk %s is still running", disk->dst);
        } else {
            VIR_DEBUG("Drive mirror on disk %s is gone", disk->dst);
            qemuBlockJobSyncEnd(vm, QEMU_ASYNC_JOB_NONE, disk);
            diskPriv->migrating = false;
        }
    }

    if (qemuMigrationSrcNBDCopyCancel(driver, vm, false,
                                      QEMU_ASYNC_JOB_NONE, NULL) < 0)
        goto endsyncjob;

    ret = 0;

 cleanup:
    virHashFree(blockJobs);
    return ret;

 endsyncjob:
    if (storage) {
        for (i = 0; i < vm->def->ndisks; i++) {
            virDomainDiskDefPtr disk = vm->def->disks[i];
            qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

            if (diskPriv->migrating) {
                qemuBlockJobSyncEnd(vm, QEMU_ASYNC_JOB_NONE, disk);
                diskPriv->migrating = false;
            }
        }
    }
    goto cleanup;
}


// set async job with migration op and mask
// it's called only once at both source and dst to prevent other operation
// so that during migration, other operation for this vm(like qmp, qga is blocked)!!!
// to pretect the vm state consistent between source and dst
static int
qemuMigrationJobStart(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      qemuDomainAsyncJob job,
                      unsigned long apiFlags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainJobOperation op;
    unsigned long long mask;

    if (job == QEMU_ASYNC_JOB_MIGRATION_IN) {
        // dst libvirtd calls me
        // as mask is NONE, NO job is prevent.
        op = VIR_DOMAIN_JOB_OPERATION_MIGRATION_IN;
        mask = QEMU_JOB_NONE;
    } else {
        // source libvirtd calls me, some operation are allowed at source!!!
        op = VIR_DOMAIN_JOB_OPERATION_MIGRATION_OUT;
        // QEMU_JOB_DEFAULT_MASK:
        // normal job(QMP job) like  abort job, query, destroy, suspend, migration_op job is allowed
        // agent job is not allowed!!!
        //
        // virsh domjobabort vm100
        // virsh domblkstat vm100
        // virsh destroy vm100
        // virsh suspend vm100
        // virsh domjobabort vm100  (abort the current running async job [migration job acutally]) check qemuDomainAbortJob()
        //
        // QEMU_JOB_MIGRATION_OP job
        // virsh migrate-setspeed vm100 20
        // virsh migrate-setmaxdowntime 100
        // virsh migrate-compcache vm100 --size 1000000
        mask = QEMU_JOB_DEFAULT_MASK |
               JOB_MASK(QEMU_JOB_SUSPEND) |
               JOB_MASK(QEMU_JOB_MIGRATION_OP);
    }

    // set async job to job.AsycActive and operation
    if (qemuDomainObjBeginAsyncJob(driver, vm, job, op, apiFlags) < 0)
        return -1;

    priv->job.current->statsType = QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION;

    // set mask of async
    qemuDomainObjSetAsyncJobMask(vm, mask);
    return 0;
}

static void
qemuMigrationJobSetPhase(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuMigrationJobPhase phase)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (phase < priv->job.phase) {
        VIR_ERROR(_("migration protocol going backwards %s => %s"),
                  qemuMigrationJobPhaseTypeToString(priv->job.phase),
                  qemuMigrationJobPhaseTypeToString(phase));
        return;
    }

    qemuDomainObjSetJobPhase(driver, vm, phase);
}

static void
qemuMigrationJobStartPhase(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           qemuMigrationJobPhase phase)
{
    // qemuMigrationJobStartPhase == qemuMigrationJobSetPhase
    // TODO: why not use qemuMigrationJobSetPhase instead???
    qemuMigrationJobSetPhase(driver, vm, phase);
}

static void
qemuMigrationJobContinue(virDomainObjPtr vm)
{
    qemuDomainObjReleaseAsyncJob(vm);
}

static bool
qemuMigrationJobIsActive(virDomainObjPtr vm,
                         qemuDomainAsyncJob job)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->job.asyncActive != job) {
        const char *msg;

        if (job == QEMU_ASYNC_JOB_MIGRATION_IN)
            msg = _("domain '%s' is not processing incoming migration");
        else
            msg = _("domain '%s' is not being migrated");

        virReportError(VIR_ERR_OPERATION_INVALID, msg, vm->def->name);
        return false;
    }
    return true;
}

// Job Finished is called when migration FINISH in both sides or error happens at both side
static void
qemuMigrationJobFinish(virQEMUDriverPtr driver, virDomainObjPtr vm)
{
    qemuDomainObjEndAsyncJob(driver, vm);
}


static void
qemuMigrationDstErrorFree(void *data,
                       const void *name ATTRIBUTE_UNUSED)
{
    virErrorPtr err = data;
    virFreeError(err);
}

int
qemuMigrationDstErrorInit(virQEMUDriverPtr driver)
{
    driver->migrationErrors = virHashAtomicNew(64, qemuMigrationDstErrorFree);
    if (driver->migrationErrors)
        return 0;
    else
        return -1;
}

/**
 * This function consumes @err; the caller should consider the @err pointer
 * invalid after calling this function.
 */
void
qemuMigrationDstErrorSave(virQEMUDriverPtr driver,
                          const char *name,
                          virErrorPtr err)
{
    if (!err)
        return;

    VIR_DEBUG("Saving incoming migration error for domain %s: %s",
              name, err->message);
    if (virHashAtomicUpdate(driver->migrationErrors, name, err) < 0) {
        VIR_WARN("Failed to save migration error for domain '%s'", name);
        virFreeError(err);
    }
}

void
qemuMigrationDstErrorReport(virQEMUDriverPtr driver,
                            const char *name)
{
    virErrorPtr err;

    if (!(err = virHashAtomicSteal(driver->migrationErrors, name)))
        return;

    VIR_DEBUG("Restoring saved incoming migration error for domain %s: %s",
              name, err->message);
    virSetError(err);
    virFreeError(err);
}


int
qemuMigrationSrcFetchMirrorStats(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 qemuDomainAsyncJob asyncJob,
                                 qemuDomainJobInfoPtr jobInfo)
{
    size_t i;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool nbd = false;
    virHashTablePtr blockinfo = NULL;
    qemuDomainMirrorStatsPtr stats = &jobInfo->mirrorStats;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        if (QEMU_DOMAIN_DISK_PRIVATE(disk)->migrating) {
            nbd = true;
            break;
        }
    }

    if (!nbd)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    blockinfo = qemuMonitorGetAllBlockJobInfo(priv->mon);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || !blockinfo)
        return -1;

    memset(stats, 0, sizeof(*stats));

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        qemuMonitorBlockJobInfoPtr data;

        if (!diskPriv->migrating ||
            !(data = virHashLookup(blockinfo, disk->info.alias)))
            continue;

        stats->transferred += data->cur;
        stats->total += data->end;
    }

    virHashFree(blockinfo);
    return 0;
}
