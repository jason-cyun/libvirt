/*
 * qemu_agent.c: interaction with QEMU guest agent
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>

#include "qemu_agent.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virjson.h"
#include "virfile.h"
#include "virprocess.h"
#include "virtime.h"
#include "virobject.h"
#include "virstring.h"
#include "base64.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_agent");

#define LINE_ENDING "\n"

#define DEBUG_IO 0
#define DEBUG_RAW_IO 0

/* We read from QEMU until seeing a \r\n pair to indicate a
 * completed reply or event. To avoid memory denial-of-service
 * though, we must have a size limit on amount of data we
 * buffer. 10 MB is large enough that it ought to cope with
 * normal QEMU replies, and small enough that we're not
 * consuming unreasonable mem.
 */
#define QEMU_AGENT_MAX_RESPONSE (10 * 1024 * 1024)

/* When you are the first to uncomment this,
 * don't forget to uncomment the corresponding
 * part in qemuAgentIOProcessEvent as well.
 *
static struct {
    const char *type;
    void (*handler)(qemuAgentPtr mon, virJSONValuePtr data);
} eventHandlers[] = {
};
*/

typedef struct _qemuAgentMessage qemuAgentMessage;
typedef qemuAgentMessage *qemuAgentMessagePtr;

struct _qemuAgentMessage {
    // sent msg
    // txOffset: already sent bytes
    // txLength: totoal bytes
    char *txBuffer;
    int txOffset;
    int txLength;

    /* Used by the JSON monitor to hold reply / error */

    /* NOTE: rxBuffer and rxLength are not used at all
     *
     * we use rxObject which is json object parsed from json string
     */
    char *rxBuffer;
    int rxLength;
    void *rxObject; // parsed json object from _qemuAgent->buffer

    /* True
     * if rxBuffer is ready
     * Or rxObject is ready,
     * or a fatal error occurred on the monitor channel for reading
     * or when close a monitor which as msg sent.
     */
    bool finished;

    /* true for sync command */
    bool sync;
    /* id of the issued sync command, only for sync command */
    unsigned long long id;
    /* as if sync timedout, we have retry, first means the first time sync sent */
    bool first;
};


struct _qemuAgent {
    // mutex of agent same thing like qmp monitor
    virObjectLockable parent;

    virCond notify;

    int fd; // fd of host side unix file
    int watch; // watch id of this fd

    /*  true when we opened monitor
     * false when closing monitor
     */
    bool running;

    virDomainObjPtr vm;

    // agent callbacks for (destroy, eof, error)
    qemuAgentCallbacksPtr cb;

    /* If there's a command being processed this will be non-NULL
     * msg sent to guest pending for reply
     * msg also holds the json object(reply)!!!
     */
    qemuAgentMessagePtr msg;

    /* Buffer incoming data ready for Agent monitor
     * code to process & find message boundaries
     * bufferLength: total buffer len
     * bufferOffset: received bytes
     */
    size_t bufferOffset;
    size_t bufferLength;
    char *buffer; // if several reads, each read data is separated by \0 !!!

    /* If anything went wrong, this will be fed back
     * the next monitor msg */
    virError lastError;

    /* Some guest agent commands don't return anything
     * but fire up an event on qemu monitor instead.
     * Take that as indication of successful completion
     * SHUTDOWN, RESET, SUSPEND
     */
    qemuAgentEvent await_event;
};

static virClassPtr qemuAgentClass;
static void qemuAgentDispose(void *obj);

static int qemuAgentOnceInit(void)
{
    if (!VIR_CLASS_NEW(qemuAgent, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(qemuAgent)


#if DEBUG_RAW_IO
# include <c-ctype.h>
static char *
qemuAgentEscapeNonPrintable(const char *text)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    for (i = 0; text[i] != '\0'; i++) {
        if (text[i] == '\\')
            virBufferAddLit(&buf, "\\\\");
        else if (c_isprint(text[i]) || text[i] == '\n' ||
                 (text[i] == '\r' && text[i+1] == '\n'))
            virBufferAddChar(&buf, text[i]);
        else
            virBufferAsprintf(&buf, "\\x%02x", text[i]);
    }
    return virBufferContentAndReset(&buf);
}
#endif


static void qemuAgentDispose(void *obj)
{
    // when free agent, free its fields as well.
    qemuAgentPtr mon = obj;
    VIR_DEBUG("mon=%p", mon);
    if (mon->cb && mon->cb->destroy)
        (mon->cb->destroy)(mon, mon->vm);
    virCondDestroy(&mon->notify);
    VIR_FREE(mon->buffer);
    virResetError(&mon->lastError);
}

static int
qemuAgentOpenUnix(const char *monitor)
{
    struct sockaddr_un addr;
    int monfd;
    int ret = -1;

    // it's stream, so that reply for one command can be sent as two parts or more by server
    // and client gets reply may call several read() api, we should buffer them and process them when we get a whole reply
    if ((monfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to create socket"));
        return -1;
    }

    // non block, connect return immediately if server is not ready.
    // server is created by qemu process not guest agent who runs inside VM
    if (virSetNonBlock(monfd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to put monitor "
                               "into non-blocking mode"));
        goto error;
    }

    if (virSetCloseExec(monfd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set monitor "
                               "close-on-exec flag"));
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, monitor) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Agent path %s too big for destination"), monitor);
        goto error;
    }

    ret = connect(monfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to connect to monitor socket"));
        goto error;
    }

    return monfd;

 error:
    VIR_FORCE_CLOSE(monfd);
    return -1;
}

static int
qemuAgentOpenPty(const char *monitor)
{
    int monfd;

    if ((monfd = open(monitor, O_RDWR | O_NONBLOCK)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open monitor path %s"), monitor);
        return -1;
    }

    if (virSetCloseExec(monfd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set monitor close-on-exec flag"));
        goto error;
    }

    return monfd;

 error:
    VIR_FORCE_CLOSE(monfd);
    return -1;
}


/*
 * As you can see we did not process event from qga at all
 * actually, there is no event sent by QGA.
 */
static int
qemuAgentIOProcessEvent(qemuAgentPtr mon,
                        virJSONValuePtr obj)
{
    const char *type;
    VIR_DEBUG("mon=%p obj=%p", mon, obj);

    type = virJSONValueObjectGetString(obj, "event");
    if (!type) {
        VIR_WARN("missing event type in message");
        errno = EINVAL;
        return -1;
    }

/*
    for (i = 0; i < ARRAY_CARDINALITY(eventHandlers); i++) {
        if (STREQ(eventHandlers[i].type, type)) {
            virJSONValuePtr data = virJSONValueObjectGet(obj, "data");
            VIR_DEBUG("handle %s handler=%p data=%p", type,
                      eventHandlers[i].handler, data);
            (eventHandlers[i].handler)(mon, data);
            break;
        }
    }
*/
    return 0;
}

// line here is just json string from QGA stored at monitor->buffer
static int
qemuAgentIOProcessLine(qemuAgentPtr mon,
                       const char *line,
                       qemuAgentMessagePtr msg)
{
    virJSONValuePtr obj = NULL;
    int ret = -1;

    VIR_DEBUG("Line [%s]", line);

    // empty line or not json format can be treated as error
    if (!(obj = virJSONValueFromString(line))) {
        /* receiving garbage on first sync is regular situation */
        if (msg && msg->sync && msg->first) {
            VIR_DEBUG("Received garbage on sync");
            msg->finished = 1;
            return 0;
        }

        goto cleanup;
    }

    if (virJSONValueGetType(obj) != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parsed JSON reply '%s' isn't an object"), line);
        goto cleanup;
    }

    if (virJSONValueObjectHasKey(obj, "QMP") == 1) {
        ret = 0;
    } else if (virJSONValueObjectHasKey(obj, "event") == 1) {
        ret = qemuAgentIOProcessEvent(mon, obj);
    } else if (virJSONValueObjectHasKey(obj, "error") == 1 ||
               virJSONValueObjectHasKey(obj, "return") == 1) {
        // most of time we reach here
        if (msg) {
            if (msg->sync) {
                unsigned long long id;

                if (virJSONValueObjectGetNumberUlong(obj, "return", &id) < 0) {
                    // no id means it could be reply for previous cmd which timed out, but for this sync command.
                    VIR_DEBUG("Ignoring delayed reply on sync");
                    ret = 0;
                    goto cleanup;
                }

                VIR_DEBUG("Guest returned ID: %llu", id);

                if (msg->id != id) {
                    // reply for current sync command, no wake up the command issuer, return ok
                    VIR_DEBUG("Guest agent returned ID: %llu instead of %llu",
                              id, msg->id);
                    ret = 0;
                    goto cleanup;
                }
            }
            // save parsed json object, mark msg finished, wake up command issuer!!!!
            msg->rxObject = obj;
            msg->finished = 1;
            obj = NULL;
        } else {
            /*
             * there is no msg but got reply(delayed reply)
             * as msg is finished by some reason before we get reply
             * we are out of sync
             */
            VIR_DEBUG("Ignoring delayed reply");
        }

        ret = 0;
    } else {
        // json without supported keyword!!! error
        // for error, we wake up command issuer
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown JSON reply '%s'"), line);
    }

 cleanup:
    virJSONValueFree(obj);
    return ret;
}

static int qemuAgentIOProcessData(qemuAgentPtr mon,
                                  char *data,
                                  size_t len,
                                  qemuAgentMessagePtr msg)
{
    int used = 0;
    size_t i = 0;
#if DEBUG_IO
# if DEBUG_RAW_IO
    char *str1 = qemuAgentEscapeNonPrintable(data);
    VIR_ERROR("[%s]", str1);
    VIR_FREE(str1);
# else
    VIR_DEBUG("Data %zu bytes [%s]", len, data);
# endif
#endif

    while (used < len) {
        char *nl = strstr(data + used, LINE_ENDING);

        if (nl) {
            int got = nl - (data + used);
            for (i = 0; i < strlen(LINE_ENDING); i++)
                data[used + got + i] = '\0';
            // < 0 happens for empty line or line with wrong json format
            if (qemuAgentIOProcessLine(mon, data + used, msg) < 0)
                return -1;
            used += got + strlen(LINE_ENDING);
        } else {
            break;
        }
    }

    VIR_DEBUG("Total used %d bytes out of %zd available in buffer", used, len);
    return used;
}

/* This method processes data that has been received
 * from the monitor. Looking for async events and
 * replies/errors.
 */
static int
qemuAgentIOProcess(qemuAgentPtr mon)
{
    // processing received bytes in mon->buffer!!!
    int len;
    qemuAgentMessagePtr msg = NULL;

    /* See if there's a message ready for reply; that is,
     * one that has completed writing all its data.
     *
     */
    if (mon->msg && mon->msg->txOffset == mon->msg->txLength)
        // if we sent all to agent
        msg = mon->msg;

#if DEBUG_IO
# if DEBUG_RAW_IO
    char *str1 = qemuAgentEscapeNonPrintable(msg ? msg->txBuffer : "");
    char *str2 = qemuAgentEscapeNonPrintable(mon->buffer);
    VIR_ERROR(_("Process %zu %p %p [[[%s]]][[[%s]]]"),
              mon->bufferOffset, mon->msg, msg, str1, str2);
    VIR_FREE(str1);
    VIR_FREE(str2);
# else
    VIR_DEBUG("Process %zu", mon->bufferOffset);
# endif
#endif

    // len parsed bytes of mon->buffer
    // msg is NULL if we does NOT send all bytes of the command
    len = qemuAgentIOProcessData(mon,
                                 mon->buffer, mon->bufferOffset,
                                 msg);

    if (len < 0)
        return -1;

    if (len < mon->bufferOffset) {
        // move mon->buffer forward by len as the first len bytes is used!!!
        memmove(mon->buffer, mon->buffer + len, mon->bufferOffset - len);
        mon->bufferOffset -= len;
    } else {
        // here means mon->buffer is a full reply and parsed, saved at mon->msg.rxObject!!!
        // we can free the reply(raw bytes)
        VIR_FREE(mon->buffer);
        mon->bufferOffset = mon->bufferLength = 0;
    }
#if DEBUG_IO
    VIR_DEBUG("Process done %zu used %d", mon->bufferOffset, len);
#endif
    // after received reply(finished=1), wake up waiter(who sent qga command)
    if (msg && msg->finished)
        virCondBroadcast(&mon->notify);
    return len;
}


/*
 * Called when the monitor is able to write data
 * Call this function while holding the monitor lock.
 */
static int
qemuAgentIOWrite(qemuAgentPtr mon)
{
    int done;

    /* If no active message, or fully transmitted(all are sent), then no-op */
    if (!mon->msg || mon->msg->txOffset == mon->msg->txLength)
        return 0;

    /* sending the unsent part
     * if error happens, we should wake up command issuer as well
     */
    done = safewrite(mon->fd,
                     mon->msg->txBuffer + mon->msg->txOffset,
                     mon->msg->txLength - mon->msg->txOffset);

    if (done < 0) {
        if (errno == EAGAIN)
            return 0;

        virReportSystemError(errno, "%s",
                             _("Unable to write to monitor"));
        return -1;
    }
    // move offset for sent bytes
    mon->msg->txOffset += done;
    return done;
}

/*
 * Called when the monitor has incoming data to read
 * Call this function while holding the monitor lock.
 *
 * Returns -1 on error, or number of bytes read
 */
static int
qemuAgentIORead(qemuAgentPtr mon)
{
    size_t avail = mon->bufferLength - mon->bufferOffset;
    int ret = 0;

    if (avail < 1024) {
        if (mon->bufferLength >= QEMU_AGENT_MAX_RESPONSE) {
            virReportSystemError(ERANGE,
                                 _("No complete agent response found in %d bytes"),
                                 QEMU_AGENT_MAX_RESPONSE);
            return -1;
        }
        // allocate buffer for reading
        if (VIR_REALLOC_N(mon->buffer,
                          mon->bufferLength + 1024) < 0)
            return -1;
        mon->bufferLength += 1024;
        avail += 1024;
    }

    /* Read as much as we can get into our buffer,
       until we block on EAGAIN, or hit EOF */
    while (avail > 1) {
        int got;
        // read in non-block mode
        got = read(mon->fd,
                   mon->buffer + mon->bufferOffset,
                   avail - 1); // on byte used for \0
        if (got < 0) {
            if (errno == EAGAIN)
                break;
            virReportSystemError(errno, "%s",
                                 _("Unable to read from monitor"));
            ret = -1;
            break;
        }
        if (got == 0)
            break;

        /* ret: total received bytes of this loop
         * got: received bytes of this read
         * avail: left space to hold the bytes
         */
        ret += got;
        avail -= got;
        mon->bufferOffset += got;
        // as you can see for each read, we insert '\0' as separator
        mon->buffer[mon->bufferOffset] = '\0';
    }

#if DEBUG_IO
    VIR_DEBUG("Now read %zu bytes of data", mon->bufferOffset);
#endif

    return ret;
}


// reset event for this agent fd
// when process event on this fd / put msg to send / got reply with below rules.
// 1. Always add read event
// 2. Add write event if not send all.
static void qemuAgentUpdateWatch(qemuAgentPtr mon)
{
    int events =
        VIR_EVENT_HANDLE_HANGUP |
        VIR_EVENT_HANDLE_ERROR;

    if (mon->lastError.code == VIR_ERR_OK) {
        events |= VIR_EVENT_HANDLE_READABLE;

        if (mon->msg && mon->msg->txOffset < mon->msg->txLength)
            events |= VIR_EVENT_HANDLE_WRITABLE;
    }

    virEventUpdateHandle(mon->watch, events);
}


// handler for event happened at agent fd
static void
qemuAgentIO(int watch, int fd, int events, void *opaque)
{
    qemuAgentPtr mon = opaque;
    bool error = false;
    bool eof = false;

    virObjectRef(mon);
    /* lock access to the monitor and protect fd */
    virObjectLock(mon);
#if DEBUG_IO
    VIR_DEBUG("Agent %p I/O on watch %d fd %d events %d", mon, watch, fd, events);
#endif

    if (mon->fd != fd || mon->watch != watch) {
        if (events & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR))
            eof = true;
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("event from unexpected fd %d!=%d / watch %d!=%d"),
                       mon->fd, fd, mon->watch, watch);
        // error from kernel
        error = true;
    } else if (mon->lastError.code != VIR_ERR_OK) {
        if (events & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR))
            eof = true;
        error = true;
    } else {
        // events reported by kernel of agent fd
        if (events & VIR_EVENT_HANDLE_WRITABLE) {
            // write event is monitor only when we put msg to send
            if (qemuAgentIOWrite(mon) < 0)
                // error when process writing
                error = true;
            events &= ~VIR_EVENT_HANDLE_WRITABLE;
        }

        // no error and readable
        if (!error &&
            events & VIR_EVENT_HANDLE_READABLE) {
            int got = qemuAgentIORead(mon);
            events &= ~VIR_EVENT_HANDLE_READABLE;
            if (got < 0) {
                // error when process reading
                error = true;
            } else if (got == 0) {
                eof = true;
            } else {
                /* Ignore hangup/error events if we read some data, to
                 * give time for that data to be consumed */
                events = 0;

                if (qemuAgentIOProcess(mon) < 0)
                    // process reply like not json format, json without keyword, it's error
                    // we should wake up command issuer.
                    // error when process reply message
                    error = true;
            }
        }

        // no error and handup event
        if (!error &&
            events & VIR_EVENT_HANDLE_HANGUP) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("End of file from agent monitor"));
            eof = true;
            events &= ~VIR_EVENT_HANDLE_HANGUP;
        }

        // no error, no eof, error from kernel
        if (!error && !eof &&
            events & VIR_EVENT_HANDLE_ERROR) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Invalid file descriptor while waiting for monitor"));
            eof = true;
            events &= ~VIR_EVENT_HANDLE_ERROR;
        }

        // no error, other event we does not processed
        if (!error && events) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unhandled event %d for monitor fd %d"),
                           events, mon->fd);
            error = true;
        }
    }

    if (error || eof) {
        // error when processing event(error report by kernel, or libvirt)
        if (mon->lastError.code != VIR_ERR_OK) {
            /* Already have an error, so clear any new error */
            virResetLastError();
        } else {
            if (virGetLastErrorCode() == VIR_ERR_OK)
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Error while processing monitor IO"));
            /*
             * ==========================error transferring=========================================
             * copy error to monitor->lastError from thread local error
             * reset thread local error
             * thread local error is set during process read/write event with helper: virReportError/virReportSystemError
             * ==========================error transferring=========================================
             */
            virCopyLastError(&mon->lastError);
            virResetLastError();
        }

        VIR_DEBUG("Error on monitor %s", NULLSTR(mon->lastError.message));
        /* If IO process resulted in an error & we have a message,
         * then wakeup that waiter
         *
         * error can be sent error or reply error happens when processing
         */
        if (mon->msg && !mon->msg->finished) {
            mon->msg->finished = 1;
            virCondSignal(&mon->notify);
        }
    }

    qemuAgentUpdateWatch(mon);

    /* We have to unlock to avoid deadlock against command thread,
     * but is this safe ?  I think it is, because the callback
     * will try to acquire the virDomainObjPtr mutex next */
    if (eof) {
        void (*eofNotify)(qemuAgentPtr, virDomainObjPtr)
            = mon->cb->eofNotify;
        virDomainObjPtr vm = mon->vm;

        /* Make sure anyone waiting wakes up now */
        // TODO: should we do it as above we already did it???
        virCondSignal(&mon->notify);
        virObjectUnlock(mon);
        virObjectUnref(mon);

        VIR_DEBUG("Triggering EOF callback");
        (eofNotify)(mon, vm);
    } else if (error) {
        void (*errorNotify)(qemuAgentPtr, virDomainObjPtr)
            = mon->cb->errorNotify;
        virDomainObjPtr vm = mon->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&mon->notify);
        virObjectUnlock(mon);
        virObjectUnref(mon);

        VIR_DEBUG("Triggering error callback");
        (errorNotify)(mon, vm);
    } else {
        virObjectUnlock(mon);
        virObjectUnref(mon);
    }
}


qemuAgentPtr
qemuAgentOpen(virDomainObjPtr vm,
              const virDomainChrSourceDef *config,
              qemuAgentCallbacksPtr cb)
{
    qemuAgentPtr mon;

    if (!cb || !cb->eofNotify) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("EOF notify callback must be supplied"));
        return NULL;
    }

    if (qemuAgentInitialize() < 0)
        return NULL;

    if (!(mon = virObjectLockableNew(qemuAgentClass)))
        return NULL;

    mon->fd = -1;
    if (virCondInit(&mon->notify) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot initialize monitor condition"));
        virObjectUnref(mon);
        return NULL;
    }
    // bind vm with agent monitor and set its callback
    mon->vm = vm;
    mon->cb = cb;

    switch (config->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        // connect with agent, no retry as server is ready
        // if server is not ready, as above mentioned, we defer to connect
        mon->fd = qemuAgentOpenUnix(config->data.nix.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        mon->fd = qemuAgentOpenPty(config->data.file.path);
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to handle monitor type: %s"),
                       virDomainChrTypeToString(config->type));
        goto cleanup;
    }

    if (mon->fd == -1)
        goto cleanup;

    virObjectRef(mon);
    // add agent fd to event loop thread
    // this is the initial event monitored, it's reset when processing agent fd
    if ((mon->watch = virEventAddHandle(mon->fd,
                                        VIR_EVENT_HANDLE_HANGUP |
                                        VIR_EVENT_HANDLE_ERROR |
                                        VIR_EVENT_HANDLE_READABLE,
                                        qemuAgentIO,
                                        mon,
                                        virObjectFreeCallback)) < 0) {
        virObjectUnref(mon);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to register monitor events"));
        goto cleanup;
    }

    // set its state with running
    mon->running = true;
    VIR_DEBUG("New mon %p fd =%d watch=%d", mon, mon->fd, mon->watch);

    return mon;

 cleanup:
    /* We don't want the 'destroy' callback invoked during
     * cleanup from construction failure, because that can
     * give a double-unref on virDomainObjPtr in the caller,
     * so kill the callbacks now.
     */
    mon->cb = NULL;
    qemuAgentClose(mon);
    return NULL;
}


static void
qemuAgentNotifyCloseLocked(qemuAgentPtr mon)
{
    if (mon) {
        mon->running = false;

        /* If there is somebody waiting for reply
         * wake him up. No message will arrive anyway. */
        if (mon->msg && !mon->msg->finished) {
            mon->msg->finished = 1;
            virCondSignal(&mon->notify);
        }
    }
}


void
qemuAgentNotifyClose(qemuAgentPtr mon)
{
    if (!mon)
        return;

    VIR_DEBUG("mon=%p", mon);

    virObjectLock(mon);
    qemuAgentNotifyCloseLocked(mon);
    virObjectUnlock(mon);
}


void qemuAgentClose(qemuAgentPtr mon)
{
    if (!mon)
        return;

    VIR_DEBUG("mon=%p", mon);

    virObjectLock(mon);

    if (mon->fd >= 0) {
        if (mon->watch)
            // remove fd from event loop(poll())
            virEventRemoveHandle(mon->watch);
        VIR_FORCE_CLOSE(mon->fd);
    }

    qemuAgentNotifyCloseLocked(mon);
    virObjectUnlock(mon);

    virObjectUnref(mon);
}

#define QEMU_AGENT_WAIT_TIME 5

/**
 * qemuAgentSend:
 * @mon: Monitor
 * @msg: Message
 * @seconds: number of seconds to wait for the result, it can be either
 *           -2, -1, 0 or positive.
 *
 * Send @msg to agent @mon. If @seconds is equal to
 * VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK(-2), this function will block forever
 * waiting for the result. The value of
 * VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT(-1) means use default timeout value
 * and VIR_DOMAIN_QEMU_AGENT_COMMAND_NOWAIT(0) makes this function return
 * immediately without waiting. Any positive value means the number of seconds
 * to wait for the result.
 *
 * Returns: 0 on success,
 *          -2 on timeout,
 *          -1 otherwise
 */
static int qemuAgentSend(qemuAgentPtr mon,
                         qemuAgentMessagePtr msg,
                         int seconds)
{
    int ret = -1;
    unsigned long long then = 0;

    /* Check whether qemu quit unexpectedly */
    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Attempt to send command while error is set %s",
                  NULLSTR(mon->lastError.message));
        virSetError(&mon->lastError);
        return -1;
    }

    if (seconds > VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) {
        unsigned long long now;
        if (virTimeMillisNow(&now) < 0)
            return -1;
        /* use default timeout 5s for qemu agent command */
        if (seconds == VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT)
            seconds = QEMU_AGENT_WAIT_TIME;
        then = now + seconds * 1000ull;
    }

    // send just put msg at mon->msg, then update agent fd by monitor with writable event, wake up event thread(poll()) if it's blocked on poll()
    // then event thread will send mon->msg.txBuffer to agent fd
    // then I wait until event thread gets reply and processes it, then notify me by mon->notify condition.
    mon->msg = msg;
    qemuAgentUpdateWatch(mon);

    while (!mon->msg->finished) {
        // wait condtion or timeout if not reponse for longer time
        if ((then && virCondWaitUntil(&mon->notify, &mon->parent.lock, then) < 0) ||
            (!then && virCondWait(&mon->notify, &mon->parent.lock) < 0)) {
            if (errno == ETIMEDOUT) {
                virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                               _("Guest agent not available for now"));
                ret = -2;
            } else {
                virReportSystemError(errno, "%s",
                                     _("Unable to wait on agent monitor "
                                       "condition"));
            }
            goto cleanup;
        }
    }

    // while lastError is set by event thread when it processed event on agent fd.
    if (mon->lastError.code != VIR_ERR_OK) {
        // command is finished caused by error
        VIR_DEBUG("Send command resulted in error %s",
                  NULLSTR(mon->lastError.message));
        virSetError(&mon->lastError);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    mon->msg = NULL;
    qemuAgentUpdateWatch(mon);

    return ret;
}


/**
 * qemuAgentGuestSync:
 * @mon: Monitor
 *
 * Send guest-sync with unique ID
 * and wait for reply. If we get one, check if
 * received ID is equal to given.
 *
 * Returns: 0 on success,
 *          -1 otherwise
 *
 * ┌────────┐      ┌────────┐        ┌─────────┐         ┌───────┐      ┌───┐
 * │ client │◄────►│server  │ ◄─────►│ virt io │  ◄────► │serial │ ◄───►│QGA│
 * └────────┘      └────────┘        └─────────┘         └───────┘      └───┘
 *
 * As we can NOT detect if QGA is running or not
 * So for each qga command, we should sync to see if it's alive
 */
static int
qemuAgentGuestSync(qemuAgentPtr mon)
{
    int ret = -1;
    int send_ret;
    unsigned long long id;
    qemuAgentMessage sync_msg;

    memset(&sync_msg, 0, sizeof(sync_msg));
    /* set only on first sync */
    sync_msg.first = true;

 retry:
    // for second sync(retried), first is false
    if (virTimeMillisNow(&id) < 0)
        return -1;

    if (virAsprintf(&sync_msg.txBuffer,
                    "{\"execute\":\"guest-sync\", "
                    "\"arguments\":{\"id\":%llu}}\n", id) < 0)
        return -1;

    sync_msg.txLength = strlen(sync_msg.txBuffer);
    sync_msg.sync = true;
    sync_msg.id = id;

    VIR_DEBUG("Sending guest-sync command with ID: %llu", id);

    /* for sync command with timeout 5s */
    send_ret = qemuAgentSend(mon, &sync_msg,
                             VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT);

    VIR_DEBUG("qemuAgentSend returned: %d", send_ret);

    if (send_ret < 0)
        // error happens
        goto cleanup;

    if (!sync_msg.rxObject) {
        // sync needs reply, if no rxObject, retry one time
        if (sync_msg.first) {
            VIR_FREE(sync_msg.txBuffer);
            // reset first to false
            memset(&sync_msg, 0, sizeof(sync_msg));
            goto retry;
        } else {
            // only retry once, if still no response, return error
            if (mon->running)
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing monitor reply object"));
            else
                virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                               _("Guest agent disappeared while executing command"));
            goto cleanup;
        }
    }

    // got sync reply, but we do NOT use the reply data at all.
    ret = 0;

 cleanup:
    virJSONValueFree(sync_msg.rxObject);
    VIR_FREE(sync_msg.txBuffer);
    return ret;
}

static const char *
qemuAgentStringifyErrorClass(const char *klass)
{
    if (STREQ_NULLABLE(klass, "BufferOverrun"))
        return "Buffer overrun";
    else if (STREQ_NULLABLE(klass, "CommandDisabled"))
        return "The command has been disabled for this instance";
    else if (STREQ_NULLABLE(klass, "CommandNotFound"))
        return "The command has not been found";
    else if (STREQ_NULLABLE(klass, "FdNotFound"))
        return "File descriptor not found";
    else if (STREQ_NULLABLE(klass, "InvalidParameter"))
        return "Invalid parameter";
    else if (STREQ_NULLABLE(klass, "InvalidParameterType"))
        return "Invalid parameter type";
    else if (STREQ_NULLABLE(klass, "InvalidParameterValue"))
        return "Invalid parameter value";
    else if (STREQ_NULLABLE(klass, "OpenFileFailed"))
        return "Cannot open file";
    else if (STREQ_NULLABLE(klass, "QgaCommandFailed"))
        return "Guest agent command failed";
    else if (STREQ_NULLABLE(klass, "QMPBadInputObjectMember"))
        return "Bad QMP input object member";
    else if (STREQ_NULLABLE(klass, "QMPExtraInputObjectMember"))
        return "Unexpected extra object member";
    else if (STREQ_NULLABLE(klass, "UndefinedError"))
        return "An undefined error has occurred";
    else if (STREQ_NULLABLE(klass, "Unsupported"))
        return "this feature or command is not currently supported";
    else if (klass)
        return klass;
    else
        return "unknown QEMU command error";
}

/* Ignoring OOM in this method, since we're already reporting
 * a more important error
 *
 * XXX see qerror.h for different klasses & fill out useful params
 */
static const char *
qemuAgentStringifyError(virJSONValuePtr error)
{
    const char *klass = virJSONValueObjectGetString(error, "class");
    const char *detail = virJSONValueObjectGetString(error, "desc");

    /* The QMP 'desc' field is usually sufficient for our generic
     * error reporting needs. However, if not present, translate
     * the class into something readable.
     */
    if (!detail)
        detail = qemuAgentStringifyErrorClass(klass);

    return detail;
}

static const char *
qemuAgentCommandName(virJSONValuePtr cmd)
{
    const char *name = virJSONValueObjectGetString(cmd, "execute");
    if (name)
        return name;
    else
        return "<unknown>";
}

static int
qemuAgentCheckError(virJSONValuePtr cmd,
                    virJSONValuePtr reply)
{
    if (virJSONValueObjectHasKey(reply, "error")) {
        // error set by QGA, check details
        virJSONValuePtr error = virJSONValueObjectGet(reply, "error");
        char *cmdstr = virJSONValueToString(cmd, false);
        char *replystr = virJSONValueToString(reply, false);

        /* Log the full JSON formatted command & error */
        VIR_DEBUG("unable to execute QEMU agent command %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));

        /* Only send the user the command name + friendly error */
        if (!error)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute QEMU agent command '%s'"),
                           qemuAgentCommandName(cmd));
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute QEMU agent command '%s': %s"),
                           qemuAgentCommandName(cmd),
                           qemuAgentStringifyError(error));

        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    } else if (!virJSONValueObjectHasKey(reply, "return")) {
        // reply must have error or return!!!
        char *cmdstr = virJSONValueToString(cmd, false);
        char *replystr = virJSONValueToString(reply, false);

        VIR_DEBUG("Neither 'return' nor 'error' is set in the JSON reply %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to execute QEMU agent command '%s'"),
                       qemuAgentCommandName(cmd));
        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    }
    return 0;
}

static int
qemuAgentCommand(qemuAgentPtr mon,
                 virJSONValuePtr cmd,
                 virJSONValuePtr *reply,
                 bool needReply,
                 int seconds)
{

    /*
     * seconds: timeout for qga command, its value is
     * typedef enum {
     *     VIR_DOMAIN_QEMU_AGENT_COMMAND_MIN = -2,
     *     VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK = -2,       // no timeout, block for ever if no reply
     *     VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT = -1,     // 5s timeout
     *     VIR_DOMAIN_QEMU_AGENT_COMMAND_NOWAIT = 0,       // return right now, no wait/block
     *     VIR_DOMAIN_QEMU_AGENT_COMMAND_SHUTDOWN = 60,    // 60s for shutdown
     * } virDomainQemuAgentCommandTimeoutValues;
     */
    int ret = -1;
    qemuAgentMessage msg;
    char *cmdstr = NULL;
    int await_event = mon->await_event;

    *reply = NULL;

    if (!mon->running) {
        virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                       _("Guest agent disappeared while executing command"));
        return -1;
    }

    /* before send qemu agent command, we send sync to make sure, qga is alive
     * For this command timeout is 5s
     */
    if (qemuAgentGuestSync(mon) < 0)
        return -1;

    memset(&msg, 0, sizeof(msg));

    if (!(cmdstr = virJSONValueToString(cmd, false)))
        goto cleanup;
    if (virAsprintf(&msg.txBuffer, "%s" LINE_ENDING, cmdstr) < 0)
        goto cleanup;
    msg.txLength = strlen(msg.txBuffer);

    VIR_DEBUG("Send command '%s' for write, seconds = %d", cmdstr, seconds);

    ret = qemuAgentSend(mon, &msg, seconds);

    VIR_DEBUG("Receive command reply ret=%d rxObject=%p",
              ret, msg.rxObject);

    if (ret == 0) {
        if (!msg.rxObject) { // no reply from QGA
            if (await_event && !needReply) {
            /* If we haven't obtained any reply but we wait for an
             * event, then don't report this as error
             * for example: agent shutdown, reboot. suspend
             * for these agent command, await_event is set and needReply is false
             */
                VIR_DEBUG("Woken up by event %d", await_event);
            } else {
                if (mon->running)
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Missing monitor reply object"));
                else
                    virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                                   _("Guest agent disappeared while executing command"));
                ret = -1;
            }
        } else {
            // check parsed reply(json object)
            *reply = msg.rxObject;
            ret = qemuAgentCheckError(cmd, *reply);
        }
    }

 cleanup:
    VIR_FREE(cmdstr);
    // free sent buffer when finished(error/timeout/got reply)
    VIR_FREE(msg.txBuffer);

    return ret;
}

static virJSONValuePtr ATTRIBUTE_SENTINEL
qemuAgentMakeCommand(const char *cmdname,
                     ...)
{
    virJSONValuePtr obj;
    virJSONValuePtr jargs = NULL;
    va_list args;

    va_start(args, cmdname);

    if (!(obj = virJSONValueNewObject()))
        goto error;

    if (virJSONValueObjectAppendString(obj, "execute", cmdname) < 0)
        goto error;

    if (virJSONValueObjectCreateVArgs(&jargs, args) < 0)
        goto error;

    if (jargs &&
        virJSONValueObjectAppend(obj, "arguments", jargs) < 0)
        goto error;

    va_end(args);

    return obj;

 error:
    virJSONValueFree(obj);
    virJSONValueFree(jargs);
    va_end(args);
    return NULL;
}

static virJSONValuePtr
qemuAgentMakeStringsArray(const char **strings, unsigned int len)
{
    size_t i;
    virJSONValuePtr ret = virJSONValueNewArray(), str;

    if (!ret)
        return NULL;

    for (i = 0; i < len; i++) {
        str = virJSONValueNewString(strings[i]);
        if (!str)
            goto error;

        if (virJSONValueArrayAppend(ret, str) < 0) {
            virJSONValueFree(str);
            goto error;
        }
    }
    return ret;

 error:
    virJSONValueFree(ret);
    return NULL;
}

/*
 * This is called by event thread when it processed shutdown, reset, suspend event from qemu.
 * As other thread who triggered agent shutdown, reset, suspend, waiting for qemu event!!!
 * we should notify them.
 */
void qemuAgentNotifyEvent(qemuAgentPtr mon,
                          qemuAgentEvent event)
{
    virObjectLock(mon);

    VIR_DEBUG("mon=%p event=%d await_event=%d", mon, event, mon->await_event);
    if (mon->await_event == event) {
        mon->await_event = QEMU_AGENT_EVENT_NONE;
        /* thread who triggers agent command is waiting for this event, wake him up.
         * to tell him, it's done!!!
         */
        if (mon->msg && !mon->msg->finished) {
            mon->msg->finished = 1;
            virCondSignal(&mon->notify);
        }
    }

    virObjectUnlock(mon);
}

VIR_ENUM_DECL(qemuAgentShutdownMode);

VIR_ENUM_IMPL(qemuAgentShutdownMode,
              QEMU_AGENT_SHUTDOWN_LAST,
              "powerdown", "reboot", "halt");

int qemuAgentShutdown(qemuAgentPtr mon,
                      qemuAgentShutdownMode mode)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

   // make command in json object
    cmd = qemuAgentMakeCommand("guest-shutdown",
                               "s:mode", qemuAgentShutdownModeTypeToString(mode),
                               NULL);
    if (!cmd)
        return -1;

    // ================================================================
    // guest-shutdown will never return reply, hence it blocks with 60s
    // but it waits on qemu event RESET or SHUTDOWN
    // ================================================================
    //
    // so qemuAgentCommand returns in three cases here:
    // 1. qemu RESET event happens
    // 2. qemu SHUTDOWN event happens
    // 3. timed out for 60s!!!
    if (mode == QEMU_AGENT_SHUTDOWN_REBOOT)
        mon->await_event = QEMU_AGENT_EVENT_RESET;
    else
        mon->await_event = QEMU_AGENT_EVENT_SHUTDOWN;
    // convert cmd to json string
    ret = qemuAgentCommand(mon, cmd, &reply, false,
                           VIR_DOMAIN_QEMU_AGENT_COMMAND_SHUTDOWN);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/*
 * qemuAgentFSFreeze:
 * @mon: Agent
 * @mountpoints: Array of mountpoint paths to be frozen, or NULL for all
 * @nmountpoints: Number of mountpoints to be frozen, or 0 for all
 *
 * Issue guest-fsfreeze-freeze command to guest agent,
 * which freezes file systems mounted on specified mountpoints
 * (or all file systems when @mountpoints is NULL), and returns
 * number of frozen file systems on success.
 *
 * Returns: number of file system frozen on success,
 *          -1 on error.
 */
int qemuAgentFSFreeze(qemuAgentPtr mon, const char **mountpoints,
                      unsigned int nmountpoints)
{
    int ret = -1;
    virJSONValuePtr cmd, arg = NULL;
    virJSONValuePtr reply = NULL;

    if (mountpoints && nmountpoints) {
        arg = qemuAgentMakeStringsArray(mountpoints, nmountpoints);
        if (!arg)
            return -1;

        cmd = qemuAgentMakeCommand("guest-fsfreeze-freeze-list",
                                   "a:mountpoints", &arg, NULL);
    } else {
        cmd = qemuAgentMakeCommand("guest-fsfreeze-freeze", NULL);
    }

    if (!cmd)
        goto cleanup;

    // parsed json object from json string replied by QGA
    // true: means we need the reply(and there is an reply from QGA)
    if (qemuAgentCommand(mon, cmd, &reply, true,
                         VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberInt(reply, "return", &ret) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
    }

 cleanup:
    virJSONValueFree(arg);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/*
 * qemuAgentFSThaw:
 * @mon: Agent
 *
 * Issue guest-fsfreeze-thaw command to guest agent,
 * which unfreezes all mounted file systems and returns
 * number of thawed file systems on success.
 *
 * Returns: number of file system thawed on success,
 *          -1 on error.
 */
int qemuAgentFSThaw(qemuAgentPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-fsfreeze-thaw", NULL);

    if (!cmd)
        return -1;

    if (qemuAgentCommand(mon, cmd, &reply, true,
                         VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberInt(reply, "return", &ret) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
    }

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

VIR_ENUM_DECL(qemuAgentSuspendMode);

VIR_ENUM_IMPL(qemuAgentSuspendMode,
              VIR_NODE_SUSPEND_TARGET_LAST,
              "guest-suspend-ram",
              "guest-suspend-disk",
              "guest-suspend-hybrid");

int
qemuAgentSuspend(qemuAgentPtr mon,
                 unsigned int target)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand(qemuAgentSuspendModeTypeToString(target),
                               NULL);
    if (!cmd)
        return -1;

    mon->await_event = QEMU_AGENT_EVENT_SUSPEND;
    ret = qemuAgentCommand(mon, cmd, &reply, false,
                           VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuAgentArbitraryCommand(qemuAgentPtr mon,
                          const char *cmd_str,
                          char **result,
                          int timeout)
{
    /* for arbitrary qemu agent command, the timeout is set by user !!!
     * virsh qemu-agent-command --timeout 10 $qga_command
     */
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;

    *result = NULL;
    if (timeout < VIR_DOMAIN_QEMU_AGENT_COMMAND_MIN) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("guest agent timeout '%d' is "
                         "less than the minimum '%d'"),
                       timeout, VIR_DOMAIN_QEMU_AGENT_COMMAND_MIN);
        goto cleanup;
    }

    // cmd from user must be json string as well with fixed format supported by QGA
    if (!(cmd = virJSONValueFromString(cmd_str)))
        goto cleanup;

    if ((ret = qemuAgentCommand(mon, cmd, &reply, true, timeout)) < 0)
        goto cleanup;

    if (!(*result = virJSONValueToString(reply, false)))
        ret = -1;


 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuAgentFSTrim(qemuAgentPtr mon,
                unsigned long long minimum)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-fstrim",
                               "U:minimum", minimum,
                               NULL);
    if (!cmd)
        return ret;

    ret = qemuAgentCommand(mon, cmd, &reply, false,
                           VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuAgentGetVCPUs(qemuAgentPtr mon,
                  qemuAgentCPUInfoPtr *info)
{
    int ret = -1;
    size_t i;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data = NULL;
    size_t ndata;

    if (!(cmd = qemuAgentMakeCommand("guest-get-vcpus", NULL)))
        return -1;

    if (qemuAgentCommand(mon, cmd, &reply, true,
                         VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-vcpus reply was missing return data"));
        goto cleanup;
    }

    if (!virJSONValueIsArray(data)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed guest-get-vcpus data array"));
        goto cleanup;
    }

    ndata = virJSONValueArraySize(data);

    if (VIR_ALLOC_N(*info, ndata) < 0)
        goto cleanup;

    for (i = 0; i < ndata; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        qemuAgentCPUInfoPtr in = *info + i;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("array element missing in guest-get-vcpus return "
                             "value"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUint(entry, "logical-id", &in->id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'logical-id' missing in reply of guest-get-vcpus"));
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(entry, "online", &in->online) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'online' missing in reply of guest-get-vcpus"));
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(entry, "can-offline",
                                         &in->offlinable) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'can-offline' missing in reply of guest-get-vcpus"));
            goto cleanup;
        }
    }

    ret = ndata;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/* returns the value provided by the guest agent or -1 on internal error */
static int
qemuAgentSetVCPUsCommand(qemuAgentPtr mon,
                         qemuAgentCPUInfoPtr info,
                         size_t ninfo,
                         int *nmodified)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr cpus = NULL;
    virJSONValuePtr cpu = NULL;
    size_t i;

    *nmodified = 0;

    /* create the key data array */
    if (!(cpus = virJSONValueNewArray()))
        goto cleanup;

    for (i = 0; i < ninfo; i++) {
        qemuAgentCPUInfoPtr in = &info[i];

        /* don't set state for cpus that were not touched */
        if (!in->modified)
            continue;

        (*nmodified)++;

        /* create single cpu object */
        if (!(cpu = virJSONValueNewObject()))
            goto cleanup;

        if (virJSONValueObjectAppendNumberInt(cpu, "logical-id", in->id) < 0)
            goto cleanup;

        if (virJSONValueObjectAppendBoolean(cpu, "online", in->online) < 0)
            goto cleanup;

        if (virJSONValueArrayAppend(cpus, cpu) < 0)
            goto cleanup;

        cpu = NULL;
    }

    if (*nmodified == 0) {
        ret = 0;
        goto cleanup;
    }

    if (!(cmd = qemuAgentMakeCommand("guest-set-vcpus",
                                     "a:vcpus", &cpus,
                                     NULL)))
        goto cleanup;

    if (qemuAgentCommand(mon, cmd, &reply, true,
                         VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        goto cleanup;

    // BUG: why we check it again as we already checked in qemuAgentCommand()???
    if (qemuAgentCheckError(cmd, reply) < 0)
        goto cleanup;

    /* All negative values are invalid. Return of 0 is bogus since we wouldn't
     * call the guest agent so that 0 cpus would be set successfully. Reporting
     * more successfully set vcpus that we've asked for is invalid. */
    if (virJSONValueObjectGetNumberInt(reply, "return", &ret) < 0 ||
        ret <= 0 || ret > *nmodified) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest agent returned malformed or invalid return value"));
        ret = -1;
    }

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    virJSONValueFree(cpu);
    virJSONValueFree(cpus);
    return ret;
}


/**
 * Set the VCPU state using guest agent.
 *
 * Attempts to set the guest agent state for all cpus or until a proper error is
 * reported by the guest agent. This may require multiple calls.
 *
 * Returns -1 on error, 0 on success.
 */
int
qemuAgentSetVCPUs(qemuAgentPtr mon,
                  qemuAgentCPUInfoPtr info,
                  size_t ninfo)
{
    int rv;
    int nmodified;
    size_t i;

    do {
        if ((rv = qemuAgentSetVCPUsCommand(mon, info, ninfo, &nmodified)) < 0)
            return -1;

        /* all vcpus were set successfully */
        if (rv == nmodified)
            return 0;

        /* un-mark vcpus that were already set */
        for (i = 0; i < ninfo && rv > 0; i++) {
            if (!info[i].modified)
                continue;

            info[i].modified = false;
            rv--;
        }
    } while (1);

    return 0;
}


/* modify the cpu info structure to set the correct amount of cpus */
int
qemuAgentUpdateCPUInfo(unsigned int nvcpus,
                       qemuAgentCPUInfoPtr cpuinfo,
                       int ncpuinfo)
{
    size_t i;
    int nonline = 0;
    int nofflinable = 0;
    ssize_t cpu0 = -1;

    /* count the active and offlinable cpus */
    for (i = 0; i < ncpuinfo; i++) {
        if (cpuinfo[i].id == 0)
            cpu0 = i;

        if (cpuinfo[i].online)
            nonline++;

        if (cpuinfo[i].offlinable && cpuinfo[i].online)
            nofflinable++;

        /* This shouldn't happen, but we can't trust the guest agent */
        if (!cpuinfo[i].online && !cpuinfo[i].offlinable) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Invalid data provided by guest agent"));
            return -1;
        }
    }

    /* CPU0 was made offlinable in linux a while ago, but certain parts (suspend
     * to ram) of the kernel still don't cope well with that. Make sure that if
     * all remaining vCPUs are offlinable, vCPU0 will not be selected to be
     * offlined automatically */
    if (nofflinable == nonline && cpu0 >= 0 && cpuinfo[cpu0].online) {
        cpuinfo[cpu0].offlinable = false;
        nofflinable--;
    }

    /* the guest agent reported less cpus than requested */
    if (nvcpus > ncpuinfo) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest agent reports less cpu than requested"));
        return -1;
    }

    /* not enough offlinable CPUs to support the request */
    if (nvcpus < nonline - nofflinable) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Cannot offline enough CPUs"));
        return -1;
    }

    for (i = 0; i < ncpuinfo; i++) {
        if (nvcpus < nonline) {
            /* unplug */
            if (cpuinfo[i].offlinable && cpuinfo[i].online) {
                cpuinfo[i].online = false;
                cpuinfo[i].modified = true;
                nonline--;
            }
        } else if (nvcpus > nonline) {
            /* plug */
            if (!cpuinfo[i].online) {
                cpuinfo[i].online = true;
                cpuinfo[i].modified = true;
                nonline++;
            }
        } else {
            /* done */
            break;
        }
    }

    return 0;
}


int
qemuAgentGetTime(qemuAgentPtr mon,
                 long long *seconds,
                 unsigned int *nseconds)
{
    int ret = -1;
    unsigned long long json_time;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-get-time",
                               NULL);
    if (!cmd)
        return ret;

    if (qemuAgentCommand(mon, cmd, &reply, true,
                         VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberUlong(reply, "return", &json_time) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed return value"));
        goto cleanup;
    }

    /* guest agent returns time in nanoseconds,
     * we need it in seconds here */
    *seconds = json_time / 1000000000LL;
    *nseconds = json_time % 1000000000LL;
    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/**
 * qemuAgentSetTime:
 * @setTime: time to set
 * @sync: let guest agent to read domain's RTC (@setTime is ignored)
 */
int
qemuAgentSetTime(qemuAgentPtr mon,
                long long seconds,
                unsigned int nseconds,
                bool rtcSync)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    if (rtcSync) {
        cmd = qemuAgentMakeCommand("guest-set-time", NULL);
    } else {
        /* guest agent expect time with nanosecond granularity.
         * Impressing. */
        long long json_time;

        /* Check if we overflow. For some reason qemu doesn't handle unsigned
         * long long on the monitor well as it silently truncates numbers to
         * signed long long. Therefore we must check overflow against LLONG_MAX
         * not ULLONG_MAX. */
        if (seconds > LLONG_MAX / 1000000000LL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Time '%lld' is too big for guest agent"),
                           seconds);
            return ret;
        }

        json_time = seconds * 1000000000LL;
        json_time += nseconds;
        cmd = qemuAgentMakeCommand("guest-set-time",
                                   "I:time", json_time,
                                   NULL);
    }

    if (!cmd)
        return ret;

    if (qemuAgentCommand(mon, cmd, &reply, true,
                         VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuAgentGetFSInfo(qemuAgentPtr mon, virDomainFSInfoPtr **info,
                   virDomainDefPtr vmdef)
{
    size_t i, j, k;
    int ret = -1;
    size_t ndata = 0, ndisk;
    char **alias;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    virDomainFSInfoPtr *info_ret = NULL;
    virPCIDeviceAddress pci_address;

    cmd = qemuAgentMakeCommand("guest-get-fsinfo", NULL);
    if (!cmd)
        return ret;

    if (qemuAgentCommand(mon, cmd, &reply, true,
                         VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGet(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest-get-fsinfo reply was missing return data"));
        goto cleanup;
    }

    if (!virJSONValueIsArray(data)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed guest-get-fsinfo data array"));
        goto cleanup;
    }

    ndata = virJSONValueArraySize(data);
    if (ndata == 0) {
        ret = 0;
        *info = NULL;
        goto cleanup;
    }
    if (VIR_ALLOC_N(info_ret, ndata) < 0)
        goto cleanup;

    for (i = 0; i < ndata; i++) {
        /* Reverse the order to arrange in mount order */
        virJSONValuePtr entry = virJSONValueArrayGet(data, ndata - 1 - i);

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("array element '%zd' of '%zd' missing in "
                             "guest-get-fsinfo return data"),
                           i, ndata);
            goto cleanup;
        }

        if (VIR_ALLOC(info_ret[i]) < 0)
            goto cleanup;

        if (VIR_STRDUP(info_ret[i]->mountpoint,
                       virJSONValueObjectGetString(entry, "mountpoint")) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'mountpoint' missing in reply of "
                             "guest-get-fsinfo"));
            goto cleanup;
        }

        if (VIR_STRDUP(info_ret[i]->name,
                       virJSONValueObjectGetString(entry, "name")) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'name' missing in reply of guest-get-fsinfo"));
            goto cleanup;
        }

        if (VIR_STRDUP(info_ret[i]->fstype,
                       virJSONValueObjectGetString(entry, "type")) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'type' missing in reply of guest-get-fsinfo"));
            goto cleanup;
        }

        if (!(entry = virJSONValueObjectGet(entry, "disk"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'disk' missing in reply of guest-get-fsinfo"));
            goto cleanup;
        }

        if (!virJSONValueIsArray(entry)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed guest-get-fsinfo 'disk' data array"));
            goto cleanup;
        }

        ndisk = virJSONValueArraySize(entry);
        if (ndisk == 0)
            continue;
        if (VIR_ALLOC_N(info_ret[i]->devAlias, ndisk) < 0)
            goto cleanup;

        alias = info_ret[i]->devAlias;
        info_ret[i]->ndevAlias = 0;
        for (j = 0; j < ndisk; j++) {
            virJSONValuePtr disk = virJSONValueArrayGet(entry, j);
            virJSONValuePtr pci;
            int diskaddr[3], pciaddr[4];
            const char *diskaddr_comp[] = {"bus", "target", "unit"};
            const char *pciaddr_comp[] = {"domain", "bus", "slot", "function"};
            virDomainDiskDefPtr diskDef;

            if (!disk) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("array element '%zd' of '%zd' missing in "
                                 "guest-get-fsinfo 'disk' data"),
                               j, ndisk);
                goto cleanup;
            }

            if (!(pci = virJSONValueObjectGet(disk, "pci-controller"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("'pci-controller' missing in guest-get-fsinfo "
                                 "'disk' data"));
                goto cleanup;
            }

            for (k = 0; k < 3; k++) {
                if (virJSONValueObjectGetNumberInt(
                        disk, diskaddr_comp[k], &diskaddr[k]) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("'%s' missing in guest-get-fsinfo "
                                     "'disk' data"), diskaddr_comp[k]);
                    goto cleanup;
                }
            }
            for (k = 0; k < 4; k++) {
                if (virJSONValueObjectGetNumberInt(
                        pci, pciaddr_comp[k], &pciaddr[k]) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("'%s' missing in guest-get-fsinfo "
                                     "'pci-address' data"), pciaddr_comp[k]);
                    goto cleanup;
                }
            }

            pci_address.domain = pciaddr[0];
            pci_address.bus = pciaddr[1];
            pci_address.slot = pciaddr[2];
            pci_address.function = pciaddr[3];
            if (!(diskDef = virDomainDiskByAddress(
                     vmdef, &pci_address,
                     diskaddr[0], diskaddr[1], diskaddr[2])))
                continue;

            if (VIR_STRDUP(*alias, diskDef->dst) < 0)
                goto cleanup;

            if (*alias) {
                alias++;
                info_ret[i]->ndevAlias++;
            }
        }
    }

    *info = info_ret;
    info_ret = NULL;
    ret = ndata;

 cleanup:
    if (info_ret) {
        for (i = 0; i < ndata; i++)
            virDomainFSInfoFree(info_ret[i]);
        VIR_FREE(info_ret);
    }
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/*
 * qemuAgentGetInterfaces:
 * @mon: Agent monitor
 * @ifaces: pointer to an array of pointers pointing to interface objects
 *
 * Issue guest-network-get-interfaces to guest agent, which returns a
 * list of interfaces of a running domain along with their IP and MAC
 * addresses.
 *
 * Returns: number of interfaces on success, -1 on error.
 */
int
qemuAgentGetInterfaces(qemuAgentPtr mon,
                       virDomainInterfacePtr **ifaces)
{
    int ret = -1;
    size_t i, j;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr ret_array = NULL;
    size_t ifaces_count = 0;
    size_t addrs_count = 0;
    virDomainInterfacePtr *ifaces_ret = NULL;
    virHashTablePtr ifaces_store = NULL;
    char **ifname = NULL;

    /* Hash table to handle the interface alias */
    if (!(ifaces_store = virHashCreate(ifaces_count, NULL))) {
        virHashFree(ifaces_store);
        return -1;
    }

    if (!(cmd = qemuAgentMakeCommand("guest-network-get-interfaces", NULL)))
        goto cleanup;

    if (qemuAgentCommand(mon, cmd, &reply, false, VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0 ||
        qemuAgentCheckError(cmd, reply) < 0) {
        goto cleanup;
    }

    if (!(ret_array = virJSONValueObjectGet(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu agent didn't provide 'return' field"));
        goto cleanup;
    }

    if (!virJSONValueIsArray(ret_array)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu agent didn't return an array of interfaces"));
        goto cleanup;
    }

    for (i = 0; i < virJSONValueArraySize(ret_array); i++) {
        virJSONValuePtr tmp_iface = virJSONValueArrayGet(ret_array, i);
        virJSONValuePtr ip_addr_arr = NULL;
        const char *hwaddr, *ifname_s, *name = NULL;
        virDomainInterfacePtr iface = NULL;

        /* Shouldn't happen but doesn't hurt to check neither */
        if (!tmp_iface) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu agent reply missing interface entry in array"));
            goto error;
        }

        /* interface name is required to be presented */
        name = virJSONValueObjectGetString(tmp_iface, "name");
        if (!name) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu agent didn't provide 'name' field"));
            goto error;
        }

        /* Handle interface alias (<ifname>:<alias>) */
        ifname = virStringSplit(name, ":", 2);
        ifname_s = ifname[0];

        iface = virHashLookup(ifaces_store, ifname_s);

        /* If the hash table doesn't contain this iface, add it */
        if (!iface) {
            if (VIR_EXPAND_N(ifaces_ret, ifaces_count, 1) < 0)
                goto error;

            if (VIR_ALLOC(ifaces_ret[ifaces_count - 1]) < 0)
                goto error;

            if (virHashAddEntry(ifaces_store, ifname_s,
                                ifaces_ret[ifaces_count - 1]) < 0)
                goto error;

            iface = ifaces_ret[ifaces_count - 1];
            iface->naddrs = 0;

            if (VIR_STRDUP(iface->name, ifname_s) < 0)
                goto error;

            hwaddr = virJSONValueObjectGetString(tmp_iface, "hardware-address");
            if (VIR_STRDUP(iface->hwaddr, hwaddr) < 0)
                goto error;
        }

        /* Has to be freed for each interface. */
        virStringListFree(ifname);

        /* as well as IP address which - moreover -
         * can be presented multiple times */
        ip_addr_arr = virJSONValueObjectGet(tmp_iface, "ip-addresses");
        if (!ip_addr_arr)
            continue;

        if (!virJSONValueIsArray(ip_addr_arr)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed ip-addresses array"));
            goto error;
        }

        /* If current iface already exists, continue with the count */
        addrs_count = iface->naddrs;

        for (j = 0; j < virJSONValueArraySize(ip_addr_arr); j++) {
            const char *type, *addr;
            virJSONValuePtr ip_addr_obj = virJSONValueArrayGet(ip_addr_arr, j);
            virDomainIPAddressPtr ip_addr;

            if (VIR_EXPAND_N(iface->addrs, addrs_count, 1)  < 0)
                goto error;

            ip_addr = &iface->addrs[addrs_count - 1];

            /* Shouldn't happen but doesn't hurt to check neither */
            if (!ip_addr_obj) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("qemu agent reply missing IP addr in array"));
                goto error;
            }

            type = virJSONValueObjectGetString(ip_addr_obj, "ip-address-type");
            if (!type) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("qemu agent didn't provide 'ip-address-type'"
                                 " field for interface '%s'"), name);
                goto error;
            } else if (STREQ(type, "ipv4")) {
                ip_addr->type = VIR_IP_ADDR_TYPE_IPV4;
            } else if (STREQ(type, "ipv6")) {
                ip_addr->type = VIR_IP_ADDR_TYPE_IPV6;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown ip address type '%s'"),
                               type);
                goto error;
            }

            addr = virJSONValueObjectGetString(ip_addr_obj, "ip-address");
            if (!addr) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("qemu agent didn't provide 'ip-address'"
                                 " field for interface '%s'"), name);
                goto error;
            }
            if (VIR_STRDUP(ip_addr->addr, addr) < 0)
                goto error;

            if (virJSONValueObjectGetNumberUint(ip_addr_obj, "prefix",
                                                &ip_addr->prefix) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed 'prefix' field"));
                goto error;
            }
        }

        iface->naddrs = addrs_count;
    }

    VIR_STEAL_PTR(*ifaces, ifaces_ret);
    ret = ifaces_count;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    virHashFree(ifaces_store);
    return ret;

 error:
    if (ifaces_ret) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree(ifaces_ret[i]);
    }
    VIR_FREE(ifaces_ret);
    virStringListFree(ifname);

    goto cleanup;
}


int
qemuAgentSetUserPassword(qemuAgentPtr mon,
                         const char *user,
                         const char *password,
                         bool crypted)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    char *password64 = NULL;

    // password must be base64
    if (!(password64 = virStringEncodeBase64((unsigned char *)password,
                                             strlen(password))))
        goto cleanup;

    if (!(cmd = qemuAgentMakeCommand("guest-set-user-password",
                                     "b:crypted", crypted,
                                     "s:username", user,
                                     "s:password", password64,
                                     NULL)))
        goto cleanup;

    if (qemuAgentCommand(mon, cmd, &reply, true,
                         VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    VIR_FREE(password64);
    return ret;
}
