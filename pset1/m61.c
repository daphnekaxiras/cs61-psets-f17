#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>


unsigned long long nactive;           // number of active allocations [#malloc - #free]
unsigned long long active_size;       // number of bytes in active allocations
unsigned long long ntotal;            // number of allocations, total
unsigned long long total_size;        // number of bytes in allocations, total
unsigned long long nfail;             // number of failed allocation attempts
unsigned long long fail_size;         // number of bytes in failed allocation attempts
char* heap_min = NULL;                // smallest address in any region ever allocated
char* heap_max = NULL; 				  // largest address in any region ever allocated

// create a struct metadata to contain allocated data size (for use when freeing)
typedef struct metadata {
	size_t size;
	int check;
	char* check2;
	const char* file;
	int line;
	struct metadata* forward;
	struct metadata* backward;
} metadata;

// head of my metadata linked list
metadata* head = NULL;

/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

	// to protect against integer overflow, 
	// check to see if sz and metadata fit into a size_t
	// sz > (size_t) - sizeof(metadata)
	if (sz > sz + sizeof(metadata))
	{
		// if they dont fit, increase the fail counts
		// and quit because it'll fail anyway
		nfail++;
		fail_size += sz;
		return NULL;
	}

	// malloc enough space for the data and metadata
	metadata* ptr = base_malloc(sz + sizeof(metadata) + sizeof(char));

	// if malloc fails quit and increase fail count
	if (ptr == NULL)
	{
		nfail++;
		fail_size = fail_size + sz;
		return NULL;
	}

	// set metadata to reflect size and check for sanity check later
	ptr->size = sz;
	ptr->check = 0xdeadbeef;

	// set new pointer to point at data after metadata
	char* alloc = (char*) ptr + sizeof(metadata);

	alloc[sz] = 'D';

	// after successful malloc increase counts
	nactive++;
	ntotal++;
	active_size = active_size + sz;
	total_size = total_size + sz;

	// increase heap_min appropriately
	if (heap_min == NULL || alloc < heap_min)
	{
		heap_min = alloc;
	}

	// increase heap_max appropriately
	if (heap_max == NULL || alloc > heap_max)
	{
		heap_max = alloc + sz;
	}

	ptr->forward = head;
    ptr->backward = NULL;
    if (head)
        head->backward = ptr;
    head = ptr;

	ptr->file = file;
	ptr->line = line;
	ptr->check2 = alloc;

	// return pointer to data
	return alloc;
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc and friends. If
///    `ptr == NULL`, does nothing. The free was called at location
///    `file`:`line`.

void m61_free(void *ptr, const char *file, int line) {

    (void) file, (void) line;   // avoid uninitialized variable warnings

	if (ptr == NULL)
	{
		return;
	}

	if ((char*) ptr > heap_max || (char*) ptr < heap_min)
	{
		printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
		abort();
	}

	metadata* data = (metadata*) ((char*) ptr - sizeof(metadata));
	
	if ((int) data % 8 != 0 || data->check2 != ptr)
	{
		printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", file, line, ptr);

		metadata* temp = head;

		while (temp)
		{
		
			if ((char*) ptr > (char*) temp + sizeof(metadata) && (char*) ptr < (char*) temp + sizeof(metadata) + temp->size)
			{
				int middle = (char*) ptr - (char*) temp - sizeof(metadata);

				printf("  %s:%d: 0x833306c is %d bytes inside a %lu byte region allocated here\n", temp->file, temp->line, middle, temp->size);
			}
		
			temp = temp->forward;
		}
		
		abort();
	}

	if (data->check != (int) 0xdeadbeef)
	{
		printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
		abort();
	}

	if (data->backward && data->forward)
	{
		if (data->backward->forward != data || data->forward->backward != data) {
			printf("MEMORY BUG: %s:%d: invalid free of pointer %p\n", file, line, ptr);	
			abort();	
		}
	}

	if (((char*) ptr)[data->size] != 'D') {
		printf("MEMORY BUG: %s:%d: detected wild write during free of pointer %p\n", file, line, ptr);
		abort();
	}

	if (data->forward) {
		data->forward->backward = data->backward;
	}
	
	if (data->backward) {
		data->backward->forward = data->forward;
	}

	else {
		head = data->forward;
	}
 
	active_size -= data->size;
	nactive--;
	data->check = 0x0;

	base_free(ptr);
}


/// m61_realloc(ptr, sz, file, line)
///    Reallocate the dynamic memory pointed to by `ptr` to hold at least
///    `sz` bytes, returning a pointer to the new block. If `ptr` is NULL,
///    behaves like `m61_malloc(sz, file, line)`. If `sz` is 0, behaves
///    like `m61_free(ptr, file, line)`. The allocation request was at
///    location `file`:`line`.

void* m61_realloc(void* ptr, size_t sz, const char* file, int line) {
    void* new_ptr = NULL;
    if (sz) {
        new_ptr = m61_malloc(sz, file, line);
    }
    
    if (ptr && new_ptr) 
    {

		metadata* data = (metadata*) ((char*) ptr - sizeof(metadata));

		if (data->check == (int) 0xdeadbeef)
		{
			memcpy(new_ptr, ptr, data->size > sz ? sz : data->size);
		}
		

    }
    m61_free(ptr, file, line);
    return new_ptr;
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    is initialized to zero. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, int line) {

	if (sz == 0)
	{
		nfail++;
		return NULL;
	}

//	if  nmemb * sz / sz != nmemb)
	if (sz > ((size_t) -1) / nmemb)
	{
		nfail++;
		fail_size += sz;
		return NULL;
	}
    
    void* ptr = m61_malloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


/// m61_getstatistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_getstatistics(struct m61_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    //memset(stats, 255, sizeof(struct m61_statistics));
    stats->nactive = nactive;
    stats->ntotal = ntotal;
    stats->nfail = nfail;
    stats->active_size = active_size;
    stats->total_size = total_size;
    stats->fail_size = fail_size;
    stats->heap_min = heap_min;
    stats->heap_max = heap_max;
}



/// m61_printstatistics()
///    Print the current memory statistics.

void m61_printstatistics(void) {
    struct m61_statistics stats;
    m61_getstatistics(&stats);

    printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_printleakreport()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_printleakreport(void) {

	metadata* temp = head;

	while (temp != NULL)
	{
		if (temp->check == (int) 0xdeadbeef)
		{
			printf("LEAK CHECK: %s:%d: allocated object %p with size %lu\n", temp->file, temp->line, (char*) temp + sizeof(metadata), temp->size);
		}

		temp = temp->forward;
	}
    
}