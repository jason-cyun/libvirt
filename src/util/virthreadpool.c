/*
 * virthreadpool.c: a generic thread pool implementation
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2010 Hu Tao
 * Copyright (C) 2010 Daniel P. Berrange
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
 * Authors:
 *     Hu Tao <hutao@cn.fujitsu.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virthreadpool.h"
#include "viralloc.h"
#include "virthread.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _virThreadPoolJob virThreadPoolJob;
typedef virThreadPoolJob *virThreadPoolJobPtr;

struct _virThreadPoolJob {
    virThreadPoolJobPtr prev;
    virThreadPoolJobPtr next;
    unsigned int priority;

    void *data;
};

typedef struct _virThreadPoolJobList virThreadPoolJobList;
typedef virThreadPoolJobList *virThreadPoolJobListPtr;

struct _virThreadPoolJobList {
    /*
     *   head                                                                            tail
     *     │                                                                              │
     *     ▼                                                                              ▼
     * ┌───────┐             ┌──────┐              ┌───────┐            ┌─────┐          ┌────────┐
     * │       ├───────────► │      │ ───────────► │       │ ─────────► │     │ ───────► │        │
     * │ normal│             │ prio │              │ normal│            │ prio│          │ normal │
     * │       │◄─────────── │      │◄──────────── │       │ ◄────────  │     │ ◄─────── │        │
     * └───────┘             └──────┘              └───────┘            └─────┘          └────────┘
     *                         ▲
     *                         │
     *                      firstPrio
     */
    virThreadPoolJobPtr head;
    virThreadPoolJobPtr tail;
    // the first prio job in the list
    virThreadPoolJobPtr firstPrio;
};


/*
 * Actually, there are two thread pools here
 * 1. rpc worker pool
 * 2. qemu driver pool
 */
struct _virThreadPool {
    // pool is destroying
    bool quit;

    // job executed function called by each worker in the same pool
    //
    // thread entry point: virThreadPoolWorker (general entry point)
    // rpc pool job func: virThreadPoolWorker
    // other pool with different functions!!!
    virThreadPoolJobFunc jobFunc;
    // name of job function
    const char *jobFuncName;
    // opaque for each job function(different for different pools)
    void *jobOpaque;


    // normal and prio job list of this pool
    virThreadPoolJobList jobList;
    // pending jobs(both normal, prio) in the pool
    size_t jobQueueDepth;

    // mutex of this pool, normal job and prio job list share the same lock
    virMutex mutex;
    // condition of this normal job list, used for waking up worker when job comes in the pool
    virCond cond;

    virCond quit_cond;

    // As normal workers can expand dynamically, here are worker limit
    // but after expanded, it never shrinks back!!!
    // nWorkers==minWorkers when initializing
    size_t maxWorkers;
    size_t minWorkers;
    // free worker, when there is no job, freeWorkers == nWorkers
    size_t freeWorkers;
    // current running normal workers, nWorkers increases when expand, decrease when thread quits
    size_t nWorkers;
    // all pthreads(for normal workers)
    virThreadPtr workers;

    // below are initialized when only prio worker is set.
    // prio workers(maxPrioWorkers==nPrioWorkers when initializing)
    // nPrioWorkers can be smaller if a prio worker quits for some reason
    size_t maxPrioWorkers;
    size_t nPrioWorkers;
    // all pthreads(for prio workers)
    virThreadPtr prioWorkers;
    // condition of this prio job list, used for waking up worker when prio job comes in the pool
    virCond prioCond;
};

struct virThreadPoolWorkerData {
    virThreadPoolPtr pool;
    virCondPtr cond;
    bool priority;
};

/* Test whether the worker needs to quit if the current number of workers @count
 * is greater than @limit actually allows.
 */
static inline bool virThreadPoolWorkerQuitHelper(size_t count, size_t limit)
{
    return count > limit;
}

// both normal worker and prio worker call this.
// prio worker only processes prio job
// while normal worker processes both
static void virThreadPoolWorker(void *opaque)
{
    struct virThreadPoolWorkerData *data = opaque;
    virThreadPoolPtr pool = data->pool;
    // cond either normal or priority condition!!!
    virCondPtr cond = data->cond;
    bool priority = data->priority;
    size_t *curWorkers = priority ? &pool->nPrioWorkers : &pool->nWorkers;
    size_t *maxLimit = priority ? &pool->maxPrioWorkers : &pool->maxWorkers;
    virThreadPoolJobPtr job = NULL;

    VIR_FREE(data);

    virMutexLock(&pool->mutex);

    while (1) {
        /* In order to support async worker termination, we need ensure that
         * both busy and free workers know if they need to terminated. Thus,
         * busy workers need to check for this fact before they start waiting for
         * another job (and before taking another one from the queue); and
         * free workers need to check for this right after waking up.
         *
         * In case, user calls API to decrease the max worker
         * in this case, the worker may quit because of exceeding the limit.
         */
        if (virThreadPoolWorkerQuitHelper(*curWorkers, *maxLimit))
            goto out;

        /* now we have the pool lock, check condition
         * pool is not quitting, joblist is empty, i have nothing to do
         */
        while (!pool->quit &&
               ((!priority && !pool->jobList.head) || // normal worker
                (priority && !pool->jobList.firstPrio))) { // prio worker
            if (!priority)
                // increase free worker as no job in the job list
                pool->freeWorkers++;
            // block here, until job comes in
            // cond either normal or priority condition!!!
            if (virCondWait(cond, &pool->mutex) < 0) {
                if (!priority)
                    pool->freeWorkers--;
                goto out;
            }
            // starts to work, not free anymore
            // go to next loop, in that case, joblist is not empty, jump out while loop here
            if (!priority)
                pool->freeWorkers--;

            if (virThreadPoolWorkerQuitHelper(*curWorkers, *maxLimit))
                goto out;
        }

        if (pool->quit) // pool is destroying, quit myself.
            break;

        // as you can see priority worker only process priority jobs!!!
        // but normal worker processes from head to tail, no matter what job type is
        if (priority) {
            job = pool->jobList.firstPrio;
        } else {
            job = pool->jobList.head;
        }

        // update firstPrio when job is out
        if (job == pool->jobList.firstPrio) {
            // As job is being processed, move firstPrio job to next priority job.
            virThreadPoolJobPtr tmp = job->next;
            while (tmp) {
                // find the next priority job
                if (tmp->priority)
                    break;
                tmp = tmp->next;
            }
            // reset to next prio job, if no, tmp is NULL
            pool->jobList.firstPrio = tmp;
        }

        // update header and tail when job is out
        if (job->prev) // job is not head as for head its prev is NULL
            job->prev->next = job->next;
        else
            pool->jobList.head = job->next;
        if (job->next) // job is not tail as for tail, its next is NULL
            job->next->prev = job->prev;
        else
            pool->jobList.tail = job->prev;

        pool->jobQueueDepth--;

        // unlock pool when call job handler!!!
        virMutexUnlock(&pool->mutex);
        // call pool handler for this job, that means all job belongs to the same pool, use the same handler.
        (pool->jobFunc)(job->data, pool->jobOpaque);
        VIR_FREE(job);

        // lock pool again when finish the job
        virMutexLock(&pool->mutex);
    }

 out:
    if (priority)
        pool->nPrioWorkers--;
    else
        pool->nWorkers--;
    // no worker in the pool, signal pool to quit
    if (pool->nWorkers == 0 && pool->nPrioWorkers == 0)
        // the last one quited, notify thread who is destroying this pool
        virCondSignal(&pool->quit_cond);
    virMutexUnlock(&pool->mutex);
}

static int
virThreadPoolExpand(virThreadPoolPtr pool, size_t gain, bool priority)
{
    // create gain workers(normal, priority)
    // priority worker only processes priority jobs
    // while normal worker processes both type.
    virThreadPtr *workers = priority ? &pool->prioWorkers : &pool->workers;
    size_t *curWorkers = priority ? &pool->nPrioWorkers : &pool->nWorkers;
    size_t i = 0;
    struct virThreadPoolWorkerData *data = NULL;

    // expand number(gain) of virThreadPtr at the end!!!
    // after expanded, curWorkers is updated
    // curWorkers = curWorkers + gain
    if (VIR_EXPAND_N(*workers, *curWorkers, gain) < 0)
        return -1;

    for (i = 0; i < gain; i++) {
        if (VIR_ALLOC(data) < 0)
            goto error;

        data->pool = pool;
        data->cond = priority ? &pool->prioCond : &pool->cond;
        data->priority = priority;

        // new create thread should use new appended slot for virThreadPtr
        // but not overwrite the existing thread, BUG here???
        // use &(*workers)[i+previous_count]
        if (virThreadCreateFull(&(*workers)[i],
                                false,
                                virThreadPoolWorker,
                                pool->jobFuncName,
                                true,
                                data) < 0) {
            VIR_FREE(data);
            virReportSystemError(errno, "%s", _("Failed to create thread"));
            goto error;
        }
    }

    return 0;

 error:
    *curWorkers -= gain - i;
    return -1;
}

virThreadPoolPtr
virThreadPoolNewFull(size_t minWorkers,
                     size_t maxWorkers,
                     size_t prioWorkers,
                     virThreadPoolJobFunc func,
                     const char *funcName,
                     void *opaque)
{
    virThreadPoolPtr pool;

    if (minWorkers > maxWorkers)
        minWorkers = maxWorkers;

    if (VIR_ALLOC(pool) < 0)
        return NULL;

    // as you can see it's not cycled
    // for cycled bi-direction, tail = head
    pool->jobList.tail = pool->jobList.head = NULL;

    pool->jobFunc = func;
    pool->jobFuncName = funcName;
    pool->jobOpaque = opaque;

    // mutex of this pool
    if (virMutexInit(&pool->mutex) < 0)
        goto error;
    // normal job condition
    if (virCondInit(&pool->cond) < 0)
        goto error;
    // quit condition
    if (virCondInit(&pool->quit_cond) < 0)
        goto error;

    pool->minWorkers = minWorkers;
    pool->maxWorkers = maxWorkers;
    pool->maxPrioWorkers = prioWorkers;

    // initialization worker is minWorkers, later on we may increase workers
    // create normal worker
    if (virThreadPoolExpand(pool, minWorkers, false) < 0)
        goto error;

    if (prioWorkers) {
        // prio job condition
        if (virCondInit(&pool->prioCond) < 0)
            goto error;

        // create priority worker
        if (virThreadPoolExpand(pool, prioWorkers, true) < 0)
            goto error;
    }

    return pool;

 error:
    virThreadPoolFree(pool);
    return NULL;

}

void virThreadPoolFree(virThreadPoolPtr pool)
{
    virThreadPoolJobPtr job;
    bool priority = false;

    if (!pool)
        return;

    virMutexLock(&pool->mutex);
    // make pool as quitting
    pool->quit = true;
    if (pool->nWorkers > 0)
        // wake up all normal workers to quit
        virCondBroadcast(&pool->cond);
    if (pool->nPrioWorkers > 0) {
        priority = true;
        // wake up all prio workers to quit
        virCondBroadcast(&pool->prioCond);
    }

    while (pool->nWorkers > 0 || pool->nPrioWorkers > 0)
        // wait until all workers quit
        ignore_value(virCondWait(&pool->quit_cond, &pool->mutex));

    while ((job = pool->jobList.head)) {
        // as all workers quits, free pending jobs if present
        pool->jobList.head = pool->jobList.head->next;
        VIR_FREE(job);
    }

    // TODO: safe to move VIR_FREE(pool->workers) below unlock???
    // or move VIR_FREE(pool->prioWorkers) above unlock???
    VIR_FREE(pool->workers);
    virMutexUnlock(&pool->mutex);
    virMutexDestroy(&pool->mutex);
    virCondDestroy(&pool->quit_cond);
    virCondDestroy(&pool->cond);
    if (priority) {
        VIR_FREE(pool->prioWorkers);
        virCondDestroy(&pool->prioCond);
    }
    VIR_FREE(pool);
}


size_t virThreadPoolGetMinWorkers(virThreadPoolPtr pool)
{
    size_t ret;

    virMutexLock(&pool->mutex);
    ret = pool->minWorkers;
    virMutexUnlock(&pool->mutex);

    return ret;
}

size_t virThreadPoolGetMaxWorkers(virThreadPoolPtr pool)
{
    size_t ret;

    virMutexLock(&pool->mutex);
    ret = pool->maxWorkers;
    virMutexUnlock(&pool->mutex);

    return ret;
}

size_t virThreadPoolGetPriorityWorkers(virThreadPoolPtr pool)
{
    size_t ret;

    virMutexLock(&pool->mutex);
    ret = pool->nPrioWorkers;
    virMutexUnlock(&pool->mutex);

    return ret;
}

size_t virThreadPoolGetCurrentWorkers(virThreadPoolPtr pool)
{
    size_t ret;

    virMutexLock(&pool->mutex);
    ret = pool->nWorkers;
    virMutexUnlock(&pool->mutex);

    return ret;
}

size_t virThreadPoolGetFreeWorkers(virThreadPoolPtr pool)
{
    size_t ret;

    virMutexLock(&pool->mutex);
    ret = pool->freeWorkers;
    virMutexUnlock(&pool->mutex);

    return ret;
}

size_t virThreadPoolGetJobQueueDepth(virThreadPoolPtr pool)
{
    size_t ret;

    virMutexLock(&pool->mutex);
    ret = pool->jobQueueDepth;
    virMutexUnlock(&pool->mutex);

    return ret;
}

/*
 * @priority - job priority
 * Return: 0 on success, -1 otherwise
 *
 * Add a job to thread pool
 * As thread pool has only one queue(normal and prior job linked together)!!!
 * so when add a job must know  what type it is.
 */
int virThreadPoolSendJob(virThreadPoolPtr pool,
                         unsigned int priority,
                         void *jobData)
{
    virThreadPoolJobPtr job;

    virMutexLock(&pool->mutex);
    if (pool->quit)
        goto error;

    // each worker is a pthread
    // free normal worker is less than pending jobs, expand 1 normal worker(start a thread)
    if (pool->freeWorkers - pool->jobQueueDepth <= 0 &&
        pool->nWorkers < pool->maxWorkers &&
        // create a new normal worker
        virThreadPoolExpand(pool, 1, false) < 0)
        goto error;

    if (VIR_ALLOC(job) < 0)
        goto error;

    job->data = jobData;
    // indicate I'm a prio job
    job->priority = priority;

    // as you can see it's bi-direction link but not cycled!!!
    job->prev = pool->jobList.tail;
    if (pool->jobList.tail)
        pool->jobList.tail->next = job;
    // add the job to the tail(no matter it's prio or normal job)
    // they share the same list!!!
    pool->jobList.tail = job;

    if (!pool->jobList.head)
        pool->jobList.head = job;

    if (priority && !pool->jobList.firstPrio)
        pool->jobList.firstPrio = job;

    // increase pending job depth
    pool->jobQueueDepth++;

    // wake up one normal worker who can process prio job as well
    // it processes job from head to tail(no matter what type it is)
    virCondSignal(&pool->cond);
    if (priority)
        // wake up one prio worker who processes prio job only.
        virCondSignal(&pool->prioCond);

    // NOTE: both prio worker and normal worker need to get pool lock for processing the job.
    virMutexUnlock(&pool->mutex);
    return 0;

 error:
    virMutexUnlock(&pool->mutex);
    return -1;
}

/*
 * update max limit example:
 * previous: max: 10, min:5, running: 8(it never shutdowns 8 to min), min means the least, used when pool is creating.
 * now max: 5, wake up all running ones, the first waken three of them will quits due to this update
 * now max: 9, wake up all running ones, No one will quit as running number is still under max!!!
 */
int
virThreadPoolSetParameters(virThreadPoolPtr pool,
                           long long int minWorkers,
                           long long int maxWorkers,
                           long long int prioWorkers)
{
    size_t max;
    size_t min;

    virMutexLock(&pool->mutex);

    max = maxWorkers >= 0 ? maxWorkers : pool->maxWorkers;
    min = minWorkers >= 0 ? minWorkers : pool->minWorkers;
    if (min > max) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("minWorkers cannot be larger than maxWorkers"));
        goto error;
    }

    if (minWorkers >= 0) {
        // min is larger than before, expands min running one
        if ((size_t) minWorkers > pool->nWorkers &&
            virThreadPoolExpand(pool, minWorkers - pool->nWorkers,
                                false) < 0)
            goto error;
        pool->minWorkers = minWorkers;
    }

    if (maxWorkers >= 0) {
        pool->maxWorkers = maxWorkers;
        virCondBroadcast(&pool->cond);
    }

    if (prioWorkers >= 0) {
        if (prioWorkers < pool->nPrioWorkers) {
            // wake up all blocked ones, some will quit when they get pool lock.
            virCondBroadcast(&pool->prioCond);
        } else if ((size_t) prioWorkers > pool->nPrioWorkers &&
                   virThreadPoolExpand(pool, prioWorkers - pool->nPrioWorkers,
                                       true) < 0) {
            goto error;
        }
        pool->maxPrioWorkers = prioWorkers;
    }

    virMutexUnlock(&pool->mutex);
    return 0;

 error:
    virMutexUnlock(&pool->mutex);
    return -1;
}
