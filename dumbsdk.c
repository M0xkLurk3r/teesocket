#include "dumbsdk.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct _worker_thread_data {
	struct config* conf;
	const int* pipesin;
	const int* pipesout;
} worker_thread_data;

/**
 * Also a demo of teesock plugin
 * 
 */
void* routine(void* data) {
	worker_thread_data* tdata = (worker_thread_data *) data;
	struct config*	conf = tdata->conf;
	const int*			pipesin = tdata->pipesin;
	const int*			pipesout = tdata->pipesout;
	void*			routine_buf = malloc(32768);
	
	free(tdata);
	
	for (;;) {
		size_t readlen = read(pipesin[0], routine_buf, 32768);
		write(pipesout[0], routine_buf, readlen);
	}
}

void __dumb_teesocket_init(struct config* conf, const int pipesin[], const int pipesout[]) {
	pthread_t worker_thread;
	worker_thread_data* data = (worker_thread_data *) malloc(sizeof(worker_thread_data));
	data->conf = conf;
	data->pipesin = pipesin;
	data->pipesout = pipesout;
	pthread_create(&worker_thread, NULL, routine, data);
}
