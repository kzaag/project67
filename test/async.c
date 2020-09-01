#include <stdio.h>
#include <stdlib.h>

#include "async.h"
#include "cmn.h"

static p67_async_t lock = P67_ASYNC_INTIIALIZER;
const size_t tc = 1000;
static size_t atc = tc;
const int intervalms = 1;
static p67_async_t state = 0;

P67_CMN_NO_PROTO_ENTER
static void *
sync_printf(
P67_CMN_NO_PROTO_EXIT
    void * args)
{
    if(p67_mutex_lock(&lock) != 0) {
        p67_err_print_err("during lock: ", p67_err_eerrno);
        exit(2);
    }
 
    //int id = *(int *)args;

    p67_cmn_sleep_ms(intervalms);
    //printf("%d says hi%d\n", id);
    if((--atc) == 0)
        p67_mutex_set_state(&state, 0, 1);

    p67_mutex_unlock(&lock);

    return NULL;
}

/*
    expected behaviour:
        N threads get created
        each M miliseconds one of those threads print notification.
        once all threads are done primary thread gets released.
        if total time spent on this operation is lesser than M*N miliseconds 
        then test fails
*/
int
main(void)
{
    p67_thread_t thr;
    int ids[tc];
    size_t i;
    unsigned long long start, end;
    p67_err err;

    printf("Testing mutex\n");

    if((err = p67_cmn_epoch_ms(&start)) != 0) {
        p67_err_print_err("mutex get start time: ", err);
        return 2;
    }

    for(i = 0; i < tc; i++) {
        ids[i] = i;
        p67_cmn_thread_create(&thr, sync_printf, &ids[i]);
    }

    if((err = p67_mutex_wait_for_change(&state, 0, -1)) != 0) {
        p67_err_print_err("mutex wait: ", err);
        return 2;
    }

    if((err = p67_cmn_epoch_ms(&end)) != 0) {
        p67_err_print_err("mutex get start time: ", err);
        return 2;
    }

    printf("Time of completion must be bigger than %lu milisecs\n", 
                tc*intervalms);

    printf("Execution time: %llu miliseconds\n", end-start);

    if((end-start) < tc*intervalms) {
        printf("Test failed\n");
        exit(2);
    } else {
        printf("Test succeeded\n");
        exit(0);
    }
}