/*
 * object_event.c: object event queue processing helpers
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2008 VirtualIron
 * Copyright (C) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Ben Guthro
 */

#include <config.h>

#include "domain_event.h"
#include "network_event.h"
#include "object_event.h"
#include "object_event_private.h"
#include "virlog.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virobject.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("conf.object_event");

/*
 * meta for each dynamically created cb if client call proper API
 * callbackID: ID in the callback list( used as identifier of this callback, will be sent back to client
 * later on client can use it to deregister this callback)
 *
 * eventID: event type
 * conn: client connection
 * key and key_filter for check matching, if matched, cb is called
 * but only one is used, either key(which dom uuid), or key_filter which is a match function
 */

struct _virObjectEventCallback {
    int callbackID;
    virClassPtr klass;
    int eventID;
    virConnectPtr conn;
    /* remoteID is optional, always set with -1 */
    int remoteID;
    bool key_filter;
    char *key;
    virObjectEventCallbackFilter filter;
    void *filter_opaque;
    virConnectObjectEventGenericCallback cb;
    // opaque is any data that will be used by sender function who send events to client!!
    // most of time it's daemonClientEventCallbackPtr passed by register api when register one event.
    /*
     * struct daemonClientEventCallback {
     *     virNetServerClientPtr client;
     *     int eventID;
     *     int callbackID;
     *     bool legacy;
     * };
     */
    void *opaque;
    virFreeCallback freecb;
    bool deleted;
    bool legacy; /* true if end user does not know callbackID */
};
typedef struct _virObjectEventCallback virObjectEventCallback;
typedef virObjectEventCallback *virObjectEventCallbackPtr;

struct _virObjectEventCallbackList {
    unsigned int nextID;
    // callback registered by user from API
    size_t count;
    virObjectEventCallbackPtr *callbacks;
};

struct _virObjectEventQueue {
    // event count in the queue
    size_t count;
    virObjectEventPtr *events;
};
typedef struct _virObjectEventQueue virObjectEventQueue;
typedef virObjectEventQueue *virObjectEventQueuePtr;

struct _virObjectEventState {
    virObjectLockable parent;
    /* The list of domain event callbacks */
    virObjectEventCallbackListPtr callbacks;
    /* The queue of object events get from server
     * then dispatch these events to callbacks
     */
    virObjectEventQueuePtr queue;
    /* Timer for flushing events queue */
    /* timer is -1 when there is no user callback registered
     * created when the first user callback registered
     */
    int timer;
    /* Flag if we're in process of dispatching */
    bool isDispatching;
};

static virClassPtr virObjectEventClass;
static virClassPtr virObjectEventStateClass;

static void virObjectEventDispose(void *obj);
static void virObjectEventStateDispose(void *obj);

static int
virObjectEventOnceInit(void)
{
    if (!VIR_CLASS_NEW(virObjectEventState, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virObjectEvent, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virObjectEvent)

/**
 * virClassForObjectEvent:
 *
 * Return the class object to be used as a parent when creating an
 * event subclass.
 */
virClassPtr
virClassForObjectEvent(void)
{
    if (virObjectEventInitialize() < 0)
        return NULL;
    return virObjectEventClass;
}


static void
virObjectEventDispose(void *obj)
{
    virObjectEventPtr event = obj;

    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->meta.name);
    VIR_FREE(event->meta.key);
}

/**
 * virObjectEventCallbackFree:
 * @list: event callback to free
 *
 * Free the memory in the domain event callback
 */
static void
virObjectEventCallbackFree(virObjectEventCallbackPtr cb)
{
    if (!cb)
        return;

    virObjectUnref(cb->conn);
    VIR_FREE(cb->key);
    VIR_FREE(cb);
}

/**
 * virObjectEventCallbackListFree:
 * @list: event callback list head
 *
 * Free the memory in the domain event callback list
 */
static void
virObjectEventCallbackListFree(virObjectEventCallbackListPtr list)
{
    size_t i;
    if (!list)
        return;

    for (i = 0; i < list->count; i++) {
        virFreeCallback freecb = list->callbacks[i]->freecb;
        if (freecb)
            (*freecb)(list->callbacks[i]->opaque);
        VIR_FREE(list->callbacks[i]);
    }
    VIR_FREE(list->callbacks);
    VIR_FREE(list);
}


/**
 * virObjectEventCallbackListCount:
 * @conn: pointer to the connection
 * @cbList: the list
 * @klass: the base event class
 * @eventID: the event ID
 * @key: optional key of per-object filtering
 * @serverFilter: true if server supports object filtering
 *
 * Internal function to count how many callbacks remain registered for
 * the given @eventID and @key; knowing this allows the client side
 * of the remote driver know when it must send an RPC to adjust the
 * callbacks on the server.  When @serverFilter is false, this function
 * returns a count that includes both global and per-object callbacks,
 * since the remote side will use a single global event to feed both.
 * When true, the count is limited to the callbacks with the same
 * @key, and where a remoteID has already been set on the callback
 * with virObjectEventStateSetRemote().  Note that this function
 * intentionally ignores the legacy field, since RPC calls use only a
 * single callback on the server to manage both legacy and modern
 * global domain lifecycle events.
 */
static int
virObjectEventCallbackListCount(virConnectPtr conn,
                                virObjectEventCallbackListPtr cbList,
                                virClassPtr klass,
                                int eventID,
                                const char *key,
                                bool serverFilter)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->filter)// filter is set only for domain qemuMonitorEvent */
            continue;
        if (cb->klass == klass &&
            cb->eventID == eventID &&
            cb->conn == conn &&
            !cb->deleted &&
            (!serverFilter ||
             (cb->remoteID >= 0 &&
              ((key && cb->key_filter && STREQ(cb->key, key)) ||
               (!key && !cb->key_filter)))))
            ret++;
    }
    return ret;
}

/**
 * virObjectEventCallbackListRemoveID:
 * @conn: pointer to the connection
 * @cbList: the list
 * @callback: the callback to remove
 * @doFreeCb: Inhibit calling the freecb
 *
 * Internal function to remove a callback from a virObjectEventCallbackListPtr
 */
static int
virObjectEventCallbackListRemoveID(virConnectPtr conn,
                                   virObjectEventCallbackListPtr cbList,
                                   int callbackID,
                                   bool doFreeCb)
{
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->callbackID == callbackID && cb->conn == conn) {
            int ret;

            ret = cb->filter ? 0 :
                (virObjectEventCallbackListCount(conn, cbList, cb->klass,
                                                 cb->eventID,
                                                 cb->key_filter ? cb->key : NULL,
                                                 cb->remoteID >= 0) - 1);

            /* @doFreeCb inhibits calling @freecb from error paths in
             * register functions to ensure the caller of a failed register
             * function won't end up with a double free error */
            if (doFreeCb && cb->freecb)
                (*cb->freecb)(cb->opaque);
            virObjectEventCallbackFree(cb);
            VIR_DELETE_ELEMENT(cbList->callbacks, i, cbList->count);
            return ret;
        }
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("could not find event callback %d for deletion"),
                   callbackID);
    return -1;
}


static int
virObjectEventCallbackListMarkDeleteID(virConnectPtr conn,
                                       virObjectEventCallbackListPtr cbList,
                                       int callbackID)
{
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->callbackID == callbackID && cb->conn == conn) {
            cb->deleted = true;
            return cb->filter ? 0 :
                virObjectEventCallbackListCount(conn, cbList, cb->klass,
                                                cb->eventID,
                                                cb->key_filter ? cb->key : NULL,
                                                cb->remoteID >= 0);
        }
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("could not find event callback %d for deletion"),
                   callbackID);
    return -1;
}


static int
virObjectEventCallbackListPurgeMarked(virObjectEventCallbackListPtr cbList)
{
    size_t n;
    for (n = 0; n < cbList->count; n++) {
        if (cbList->callbacks[n]->deleted) {
            virFreeCallback freecb = cbList->callbacks[n]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[n]->opaque);
            virObjectEventCallbackFree(cbList->callbacks[n]);

            VIR_DELETE_ELEMENT(cbList->callbacks, n, cbList->count);
            n--;
        }
    }
    return 0;
}


/**
 * virObjectEventCallbackLookup:
 * @conn: pointer to the connection
 * @cbList: the list
 * @key: the key of the object to filter on
 * @klass: the base event class
 * @eventID: the event ID
 * @callback: the callback to locate
 * @legacy: true if callback is tracked by function instead of callbackID
 * @remoteID: optionally return a known remoteID
 *
 * Internal function to determine if @callback already has a
 * callbackID in @cbList for the given @conn and other filters.  If
 * @remoteID is non-NULL, and another callback exists that can be
 * serviced by the same remote event, then set it to that remote ID.
 *
 * Return the id if found, or -1 with no error issued if not present.
 */
static int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virObjectEventCallbackLookup(virConnectPtr conn,
                             virObjectEventCallbackListPtr cbList,
                             const char *key,
                             virClassPtr klass,
                             int eventID,
                             virConnectObjectEventGenericCallback callback,
                             bool legacy,
                             int *remoteID)
{
    size_t i;

    if (remoteID)
        *remoteID = -1;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->deleted)
            continue;
        if (cb->klass == klass &&
            cb->eventID == eventID &&
            cb->conn == conn &&
            ((key && cb->key_filter && STREQ(cb->key, key)) ||
             (!key && !cb->key_filter))) {
            if (remoteID)
                *remoteID = cb->remoteID;
            if (cb->legacy == legacy &&
                cb->cb == callback)
                return cb->callbackID;
        }
    }
    return -1;
}


/**
 * virObjectEventCallbackListAddID:
 * @conn: pointer to the connection
 * @cbList: the list
 * @key: the optional key of the object to filter on
 * @filter: optional last-ditch filter callback
 * @filter_opaque: opaque data to pass to @filter
 * @klass: the base event class
 * @eventID: the event ID
 * @callback: the callback to add
 * @opaque: opaque data to pass to @callback
 * @freecb: callback to free @opaque
 * @legacy: true if callback is tracked by function instead of callbackID
 * @callbackID: filled with callback ID
 * @serverFilter: true if server supports object filtering
 *
 * Internal function to add a callback from a virObjectEventCallbackListPtr
 */
static int
virObjectEventCallbackListAddID(virConnectPtr conn,
                                virObjectEventCallbackListPtr cbList,
                                const char *key,
                                virObjectEventCallbackFilter filter,
                                void *filter_opaque,
                                virClassPtr klass,
                                int eventID,
                                virConnectObjectEventGenericCallback callback,
                                void *opaque,
                                virFreeCallback freecb,
                                bool legacy,
                                int *callbackID,
                                bool serverFilter)
{
    virObjectEventCallbackPtr cb;
    int ret = -1;
    int remoteID = -1;

    VIR_DEBUG("conn=%p cblist=%p key=%p filter=%p filter_opaque=%p "
              "klass=%p eventID=%d callback=%p opaque=%p "
              "legacy=%d callbackID=%p serverFilter=%d",
              conn, cbList, key, filter, filter_opaque, klass, eventID,
              callback, opaque, legacy, callbackID, serverFilter);

    /* Check incoming */
    if (!cbList)
        return -1;
    /* filter and filter_opaque are set only for domain qemuMonitorEvent !!
     * for other event, it's always NULL
     */

    /* If there is no additional filtering, then check if we already
     * have this callback on our list.
     * two calbacks equal must have same
     * 1. connection
     * 2. event type
     * 3. filter key
     * */
    if (!filter &&
        virObjectEventCallbackLookup(conn, cbList, key,
                                     klass, eventID, callback, legacy,
                                     serverFilter ? &remoteID : NULL) != -1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("event callback already tracked"));
        return -1;
    }
    /* Allocate new cb */
    if (VIR_ALLOC(cb) < 0)
        goto cleanup;

    // client client used for sending event to such client when necessary
    cb->conn = virObjectRef(conn);
    *callbackID = cb->callbackID = cbList->nextID++;
    cb->cb = callback;
    cb->klass = klass;
    cb->eventID = eventID;
    cb->opaque = opaque;
    cb->freecb = freecb;
    cb->remoteID = remoteID;

    if (key) {
        cb->key_filter = true;
        if (VIR_STRDUP(cb->key, key) < 0)
            goto cleanup;
    }
    cb->filter = filter;
    cb->filter_opaque = filter_opaque;
    cb->legacy = legacy;

    // add callback to the tail !!!
    if (VIR_APPEND_ELEMENT(cbList->callbacks, cbList->count, cb) < 0)
        goto cleanup;

    /* When additional filtering is being done, every client callback
     * is matched to exactly one server callback.  */
    if (filter) {
        ret = 1;
    } else {
        // check how many callbacks registers
        ret = virObjectEventCallbackListCount(conn, cbList, klass, eventID,
                                              key, serverFilter);
        if (serverFilter && remoteID < 0)
            ret++;
    }

 cleanup:
    virObjectEventCallbackFree(cb);
    return ret;
}


/**
 * virObjectEventQueueClear:
 * @queue: pointer to the queue
 *
 * Removes all elements from the queue
 */
static void
virObjectEventQueueClear(virObjectEventQueuePtr queue)
{
    size_t i;
    if (!queue)
        return;

    for (i = 0; i < queue->count; i++)
        virObjectUnref(queue->events[i]);
    VIR_FREE(queue->events);
    queue->count = 0;
}

/**
 * virObjectEventQueueFree:
 * @queue: pointer to the queue
 *
 * Free the memory in the queue. We process this like a list here
 */
static void
virObjectEventQueueFree(virObjectEventQueuePtr queue)
{
    if (!queue)
        return;

    virObjectEventQueueClear(queue);
    VIR_FREE(queue);
}

static virObjectEventQueuePtr
virObjectEventQueueNew(void)
{
    virObjectEventQueuePtr ret;

    ignore_value(VIR_ALLOC(ret));
    return ret;
}


/**
 * virObjectEventStateDispose:
 * @list: virObjectEventStatePtr to free
 *
 * Free a virObjectEventStatePtr and its members, and unregister the timer.
 */
static void
virObjectEventStateDispose(void *obj)
{
    virObjectEventStatePtr state = obj;

    VIR_DEBUG("obj=%p", state);

    virObjectEventCallbackListFree(state->callbacks);
    virObjectEventQueueFree(state->queue);

    if (state->timer != -1)
        virEventRemoveTimeout(state->timer);
}


static void virObjectEventStateFlush(virObjectEventStatePtr state);


/**
 * virObjectEventTimer:
 * @timer: id of the event loop timer
 * @opaque: the event state object
 *
 * Register this function with the event state as its opaque data as
 * the callback of a periodic timer on the event loop, in order to
 * flush the callback queue.
 */
static void
virObjectEventTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virObjectEventStatePtr state = opaque;

    /* when event pusher(other threads) puts event in the event queue
     * it starts a timer event with timeout 0, that means timer handler
     * virObjectEventTimer called after next poll() or right now, it depends where the event thread loop.
     * when poll waked up, it first check timers, then fd, so if timer is added check timers, its runs this loop
     * otherwise, next loop poll() wakeup right now, and run this timer.
     */
    virObjectEventStateFlush(state);
}


/**
 * virObjectEventStateNew:
 *
 * Allocate a new event state object.
 */
virObjectEventStatePtr
virObjectEventStateNew(void)
{
    virObjectEventStatePtr state = NULL;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(state = virObjectLockableNew(virObjectEventStateClass)))
        return NULL;

    if (VIR_ALLOC(state->callbacks) < 0)
        goto error;

    if (!(state->queue = virObjectEventQueueNew()))
        goto error;

    state->timer = -1;

    return state;

 error:
    virObjectUnref(state);
    return NULL;
}


/**
 * virObjectEventNew:
 * @klass: subclass of event to be created
 * @dispatcher: callback for dispatching the particular subclass of event
 * @eventID: id of the event
 * @id: id of the object the event describes, or 0
 * @name: name of the object the event describes
 * @uuid: uuid of the object the event describes
 * @key: key for per-object filtering
 *
 * Create a new event, with the information common to all events.
 */
void *
virObjectEventNew(virClassPtr klass,
                  virObjectEventDispatchFunc dispatcher,
                  int eventID,
                  int id,
                  const char *name,
                  const unsigned char *uuid,
                  const char *key)
{
    virObjectEventPtr event;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!virClassIsDerivedFrom(klass, virObjectEventClass)) {
        virReportInvalidArg(klass,
                            _("Class %s must derive from virObjectEvent"),
                            virClassName(klass));
        return NULL;
    }

    // create event based on klass which represent different class(events)
    // klass can be shutdown, lifecycle class
    if (!(event = virObjectNew(klass)))
        return NULL;

    // generic event object
    // each specific event must put generic event object as it's first field!!!

    /* domain event
     * struct _virDomainEventLifecycle {
     *     virDomainEvent parent;
     *     int type;
     *     int detail;
     * };
     *
     * struct _virDomainEvent {
     *     virObjectEvent parent;
     *     bool dummy;
     * }
     *
     * storage pool event
     * struct _virStoragePoolEventLifecycle {
     *     virStoragePoolEvent parent;
     *
     *     int type;
     *     int detail;
     * };
     * struct _virStoragePoolEvent {
     *     virObjectEvent parent;
     *     bool dummy;
     * };
     *
     */
    event->dispatch = dispatcher;
    event->eventID = eventID;
    event->remoteID = -1;

    if (VIR_STRDUP(event->meta.name, name) < 0 ||
        VIR_STRDUP(event->meta.key, key) < 0) {
        virObjectUnref(event);
        return NULL;
    }
    event->meta.id = id;
    if (uuid)
        memcpy(event->meta.uuid, uuid, VIR_UUID_BUFLEN);

    VIR_DEBUG("obj=%p", event);
    // event is specific type, but here we only set its generic parts
    return event;
}


/**
 * virObjectEventQueuePush:
 * @evtQueue: the object event queue
 * @event: the event to add
 *
 * Internal function to push to the back of a virObjectEventQueue
 *
 * Returns: 0 on success, -1 on failure
 */
static int
virObjectEventQueuePush(virObjectEventQueuePtr evtQueue,
                        virObjectEventPtr event)
{
    if (!evtQueue)
        return -1;

    // queue size can be extended dynamically
    // but can not be shrunk(smaller)
    if (VIR_APPEND_ELEMENT(evtQueue->events, evtQueue->count, event) < 0)
        return -1;
    return 0;
}


static bool
virObjectEventDispatchMatchCallback(virObjectEventPtr event,
                                    virObjectEventCallbackPtr cb)
{
    if (!cb)
        return false;
    // callbacked is marked deleting
    if (cb->deleted)
        return false;
    if (!virObjectIsClass(event, cb->klass))
        return false;
    if (cb->eventID != event->eventID)
        return false;
    if (cb->remoteID != event->remoteID)
        return false;

    // filter and key, both are checked if set
    if (cb->filter && !(cb->filter)(cb->conn, event, cb->filter_opaque))
        return false;

    if (cb->key_filter)
        return STREQ(event->meta.key, cb->key);
    return true;
}


static void
virObjectEventStateDispatchCallbacks(virObjectEventStatePtr state,
                                     virObjectEventPtr event,
                                     virObjectEventCallbackListPtr callbacks)
{
    size_t i;
    /* Cache this now, since we may be dropping the lock,
       and have more callbacks added. We're guaranteed not
       to have any removed */
    size_t cbCount = callbacks->count;

    for (i = 0; i < cbCount; i++) {
        virObjectEventCallbackPtr cb = callbacks->callbacks[i];

        // for each event, check each callback, if matched, callback is called
        // matched means:
        // 1. event type is same
        // 2. if dom is given, dom->uuid is equal
        // 3. remote id is same
        if (!virObjectEventDispatchMatchCallback(event, cb))
            continue;

        /* Drop the lock whle dispatching, for sake of re-entrancy */
        virObjectUnlock(state);
        /* call event dispatch which is set when event is created
         * event is created by virObjectEventNew() API
         * with input parameter:
         *
         * Domain Event: virDomainEventDispatchDefaultFunc, eventID, dom's ID, dom's name, dom's uuid, dom's uuidstr
         * Network Event: virNetworkEventDispatchDefaultFunc, eventID, 0, net->name, net->uuid, net->uuidstr
         * NodeDevice Event: virNodeDeviceEventDispatchDefaultFunc, eventId, 0, dev->name, 0, dev->name
         */
        event->dispatch(cb->conn, event, cb->cb, cb->opaque);
        virObjectLock(state);
    }
}


static void
virObjectEventStateQueueDispatch(virObjectEventStatePtr state,
                                 virObjectEventQueuePtr queue,
                                 virObjectEventCallbackListPtr callbacks)
{
    size_t i;

    for (i = 0; i < queue->count; i++) {
        /* for each event in the queue, dispatch it */
        virObjectEventStateDispatchCallbacks(state, queue->events[i],
                                             callbacks);
        virObjectUnref(queue->events[i]);
    }
    VIR_FREE(queue->events);
    queue->count = 0;
}


/**
 * virObjectEventStateQueueRemote:
 * @state: the event state object
 * @event: event to add to the queue
 * @remoteID: limit dispatch to callbacks with the same remote id
 *
 * Adds @event to the queue of events to be dispatched at the next
 * safe moment.  The caller should no longer use @event after this
 * call.  If @remoteID is non-negative, the event will only be sent to
 * callbacks where virObjectEventStateSetRemote() registered a remote
 * id.
 */
void
virObjectEventStateQueueRemote(virObjectEventStatePtr state,
                               virObjectEventPtr event,
                               int remoteID)
{
    if (!event)
        return;

    if (state->timer < 0) {
        // no user callback register, event is NOT pushed into the queue
        virObjectUnref(event);
        return;
    }

    virObjectLock(state);
    /* At client side, the built event has remoteID which is callbackID in server */
    /* event is pushed to queue if there is at least one callback
     * no matter if it's registered for this type of event
     * that means, if client register for event A, libvirt generates B, C, D etc
     * all these events will be added into the queue and try to send them to client by compare
     * each callback one by one, at last no sending, waste cpu cycle
     * should we add event only when someone is listening on this type of event, otherwise, no addition?
     * As event does not happen quickly, so it's acceptable for current solution.
     */
    event->remoteID = remoteID;
    if (virObjectEventQueuePush(state->queue, event) < 0) {
        VIR_DEBUG("Error adding event to queue");
        virObjectUnref(event);
    }

    if (state->queue->count == 1)
        // first event in the queue, update timer to now
        // so that timer handler will be called by event thread `right now`
        virEventUpdateTimeout(state->timer, 0);
    virObjectUnlock(state);
}


/**
 * virObjectEventStateQueue:
 * @state: the event state object
 * @event: event to add to the queue
 *
 * Adds @event to the queue of events to be dispatched at the next
 * safe moment.  The caller should no longer use @event after this
 * call.
 */
void
virObjectEventStateQueue(virObjectEventStatePtr state,
                         virObjectEventPtr event)
{
    // add event to event queue(state)
    // NOTE: there are several event queues, one for domain event, one for network event, node device event etc
    virObjectEventStateQueueRemote(state, event, -1);
}


static void
virObjectEventStateCleanupTimer(virObjectEventStatePtr state, bool clear_queue)
{
    /* There are still some callbacks, keep the timer. */
    if (state->callbacks->count)
        return;

    /* The timer is not registered, nothing to do. */
    if (state->timer == -1)
        return;

    // remove timer from poll as no user callbacks, no one monitor any event.
    virEventRemoveTimeout(state->timer);
    state->timer = -1;

    // as no user callback, clear events in the queue as no one cares about it.
    if (clear_queue)
        virObjectEventQueueClear(state->queue);
}


static void
virObjectEventStateFlush(virObjectEventStatePtr state)
{
    virObjectEventQueue tempQueue;

    /* We need to lock as well as ref due to the fact that we might
     * unref the state we're working on in this very function */

    // when flushing event, we lock the queue, so no more event can be added.
    virObjectRef(state);
    virObjectLock(state);
    state->isDispatching = true;

    /* Copy the queue, so we're reentrant safe when dispatchFunc drops the
     * driver lock */
    tempQueue.count = state->queue->count;
    tempQueue.events = state->queue->events;
    state->queue->count = 0;
    state->queue->events = NULL;
    if (state->timer != -1)
        /* as each time, we process all events
         * hence we reset timer with never expire
         * if later on other thread adds event, it resets timer with 0 again
         */
        virEventUpdateTimeout(state->timer, -1);

    /* dispatch all events now */
    virObjectEventStateQueueDispatch(state,
                                     &tempQueue,
                                     state->callbacks);

    /* Purge any deleted callbacks */
    virObjectEventCallbackListPurgeMarked(state->callbacks);

    /* If we purged all callbacks, we need to remove the timeout as well
     * like virObjectEventStateDeregisterID() would do.
     * if no callbacks registered by client, remove timer event
     */
    virObjectEventStateCleanupTimer(state, true);

    state->isDispatching = false;

    virObjectUnlock(state);
    virObjectUnref(state);
}


/**
 * virObjectEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: domain event state
 * @key: key of the object for event filtering
 * @klass: the base event class
 * @eventID: ID of the event type to register for
 * @cb: function to invoke when event occurs
 * @opaque: data blob to pass to @callback
 * @freecb: callback to free @opaque
 * @legacy: true if callback is tracked by function instead of callbackID
 * @callbackID: filled with callback ID
 * @serverFilter: true if server supports object filtering
 *
 * Register the function @cb with connection @conn, from @state, for
 * events of type @eventID, and return the registration handle in
 * @callbackID.
 *
 * The return value is only important when registering client-side
 * mirroring of remote events (since the public API is documented to
 * return the callbackID rather than a count).  A return of 1 means
 * that this is the first use of this type of event, so a remote event
 * must be enabled; a return larger than 1 means that an existing
 * remote event can already feed this callback.  If @serverFilter is
 * false, the return count assumes that a single global remote feeds
 * both generic and per-object callbacks, and that the event queue
 * will be fed with virObjectEventStateQueue().  If it is true, then
 * the return count assumes that the remote side is capable of per-
 * object filtering; the user must call virObjectEventStateSetRemote()
 * to record the remote id, and queue events with
 * virObjectEventStateQueueRemote().
 *
 * Returns: the number of callbacks now registered, or -1 on error.
 */
int
virObjectEventStateRegisterID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              const char *key,
                              virObjectEventCallbackFilter filter,
                              void *filter_opaque,
                              virClassPtr klass,
                              int eventID,
                              virConnectObjectEventGenericCallback cb,
                              void *opaque,
                              virFreeCallback freecb,
                              bool legacy,
                              int *callbackID,
                              bool serverFilter)
{
    int ret = -1;

    virObjectLock(state);

    /* if there is no event timer(domain event, network event depends on what stat it's), add one with never expire
     * As event timer starts for the first time when client registers one event
     * remove it when client deregister the last registered event
     *
     * Timer is added to poll only when it's the first callback from user
     * as Timer is for all event queue which is shared by all connection and domain
     *
     * for other callbacks from user, as we already have timer starts, no needed to create it
     */
    if ((state->callbacks->count == 0) &&
        (state->timer == -1) &&
        (state->timer = virEventAddTimeout(-1,
                                           // event timer handler run by event thread when expired!!!
                                           virObjectEventTimer,
                                           state, // state can be domain event queue, or network event queue, or storage pool event queue
                                                  // all use the same timer handler, state is identified by RPC API which is called
                                                  // if it's domain event register, domain event state is used
                                                  // if it's network event register, network event state is used
                                           virObjectFreeCallback)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not initialize domain event timer"));
        goto cleanup;
    }

    /* event loop has one reference, but we need one more for the
     * timer's opaque argument */
    virObjectRef(state);

    /* ret indicates how many cb is registred
     * NOTE: same event can be registered on different connections
     *       same event can NOT be registered on same connection
     */
    ret = virObjectEventCallbackListAddID(conn, state->callbacks,
                                          key, filter, filter_opaque,
                                          klass, eventID,
                                          cb, opaque, freecb,
                                          legacy, callbackID, serverFilter);

    if (ret < 0)
        virObjectEventStateCleanupTimer(state, false);

 cleanup:
    virObjectUnlock(state);
    return ret;
}


/**
 * virObjectEventStateDeregisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @callbackID: ID of the function to remove from event
 * @doFreeCb: Allow the calling of a freecb
 *
 * Unregister the function @callbackID with connection @conn,
 * from @state, for events. If @doFreeCb is false, then we
 * are being called from a remote call failure path for the
 * Event registration indicating a -1 return to the caller. The
 * caller wouldn't expect us to run their freecb function if it
 * exists, so we cannot do so.
 *
 * Returns: the number of callbacks still registered, or -1 on error
 */
int
virObjectEventStateDeregisterID(virConnectPtr conn,
                                virObjectEventStatePtr state,
                                int callbackID,
                                bool doFreeCb)
{
    int ret;

    virObjectLock(state);
    if (state->isDispatching)
        // actually this never happens as when isDispatching is true
        // thread who flushing events must have the lock,
        // so this thread blocks on virObjectLock()
        // when flushing thread unlock state, it sets isDispatching with false
        // so here when we got the lock, isDispatching is always false!!!
        ret = virObjectEventCallbackListMarkDeleteID(conn,
                                                     state->callbacks,
                                                     callbackID);
    else
        ret = virObjectEventCallbackListRemoveID(conn, state->callbacks,
                                                 callbackID, doFreeCb);

    // try to remove timer if no user callbacks
    virObjectEventStateCleanupTimer(state, true);

    virObjectUnlock(state);
    return ret;
}

/**
 * virObjectEventStateCallbackID:
 * @conn: connection associated with callback
 * @state: object event state
 * @klass: the base event class
 * @eventID: the event ID
 * @callback: function registered as a callback
 * @remoteID: optional output, containing resulting remote id
 *
 * Returns the callbackID of @callback, or -1 with an error issued if the
 * function is not currently registered.  This only finds functions
 * registered via virConnectDomainEventRegister, even if modern style
 * virConnectDomainEventRegisterAny also registers the same callback.
 */
int
virObjectEventStateCallbackID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              virClassPtr klass,
                              int eventID,
                              virConnectObjectEventGenericCallback callback,
                              int *remoteID)
{
    int ret = -1;

    virObjectLock(state);
    ret = virObjectEventCallbackLookup(conn, state->callbacks, NULL,
                                       klass, eventID, callback, true,
                                       remoteID);
    virObjectUnlock(state);

    if (ret < 0)
        virReportError(VIR_ERR_INVALID_ARG,
                       _("event callback function %p not registered"),
                       callback);
    return ret;
}


/**
 * virObjectEventStateEventID:
 * @conn: connection associated with the callback
 * @state: object event state
 * @callbackID: the callback to query
 * @remoteID: optionally output remote ID of the callback
 *
 * Query what event ID type is associated with the callback
 * @callbackID for connection @conn.  If @remoteID is non-null, it
 * will be set to the remote id previously registered with
 * virObjectEventStateSetRemote().
 *
 * Returns 0 on success, -1 on error
 */
int
virObjectEventStateEventID(virConnectPtr conn,
                           virObjectEventStatePtr state,
                           int callbackID,
                           int *remoteID)
{
    int ret = -1;
    size_t i;
    virObjectEventCallbackListPtr cbList = state->callbacks;

    virObjectLock(state);
    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->deleted)
            continue;

        if (cb->callbackID == callbackID && cb->conn == conn) {
            if (remoteID)
                *remoteID = cb->remoteID;
            ret = cb->eventID;
            break;
        }
    }
    virObjectUnlock(state);

    if (ret < 0)
        virReportError(VIR_ERR_INVALID_ARG,
                       _("event callback id %d not registered"),
                       callbackID);
    return ret;
}


/**
 * virObjectEventStateSetRemote:
 * @conn: connection associated with the callback
 * @state: object event state
 * @callbackID: the callback to adjust
 * @remoteID: the remote ID to associate with the callback
 *
 * Update @callbackID for connection @conn to record that it is now
 * tied to @remoteID, and will therefore only match events that are
 * sent with virObjectEventStateQueueRemote() with the same remote ID.
 * Silently does nothing if @callbackID is invalid.
 */
void
virObjectEventStateSetRemote(virConnectPtr conn,
                             virObjectEventStatePtr state,
                             int callbackID,
                             int remoteID)
{
    size_t i;

    virObjectLock(state);
    for (i = 0; i < state->callbacks->count; i++) {
        virObjectEventCallbackPtr cb = state->callbacks->callbacks[i];

        if (cb->deleted)
            continue;

        if (cb->callbackID == callbackID && cb->conn == conn) {
            cb->remoteID = remoteID;
            break;
        }
    }
    virObjectUnlock(state);
}
