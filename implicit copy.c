#include <string.h>
#include <stdio.h>
#include "./allocator.h"
#include "./debug_break.h"

#define BYTES_PER_LINE 32

static void * segment_start;
static size_t segment_size;
// track how many blocks are on the heap
static size_t nblock;
// track how many bytes up to the last free block header are used
static size_t nused;

size_t roundup(size_t sz, size_t mult) {
    return (sz + mult - 1) & ~(mult - 1);
}

// return whether this block is free
bool is_free(void * header) {
    return (*((size_t *)header) & 1);
}

// return the size of this block
size_t get_size(void * header) {
    return (*((size_t *)header) & 0xfffffffffffffffe);
}

// update the housekeeping info of this block
// setting it to be used and size
void mark_used(void * header, size_t size) {
    *((size_t *)header) = size;
    *((size_t *)header) &= 0xfffffffffffffffe;
}

// update the housekeeping info of this block
// setting it to be free and size
void mark_free(void * header, size_t size) {
    *((size_t *)header) = size;
    *((size_t *)header) |= 1;
}

// return the starting point of the payload of this block
void * get_payload(void * header) {
    return (char *)header + HEADER_SIZE;
}

// return the header of this block based on the payload input
void * get_header(void* payload) {
    return (char *)payload - HEADER_SIZE;
}


// return next block's header
void * get_next_header(void * header) {
    return (char *)header + get_size(header) + HEADER_SIZE;
}



bool myinit(void *heap_start, size_t heap_size) {
    segment_start = heap_start;
    segment_size = heap_size;
    nblock = 1;
    nused = HEADER_SIZE;
    // initialize the heap to be one free block
    mark_free(segment_start, segment_size - HEADER_SIZE);
    return true;
}

void *mymalloc(size_t requested_size) {
    if (requested_size == 0) {
        return NULL;
    }
    size_t allocated_size = roundup(requested_size, ALIGNMENT);
    void * cur = segment_start;
    // find a free & large enough existing block
    for (size_t i = 0; i < nblock; i++) {
        if (is_free(cur) && get_size(cur) >= allocated_size) {
            // found a free & satisfying block before reaching the last block
            if (i != nblock - 1) {
                // use this block, no resizing
                mark_used(cur, get_size(cur));
            } else {
                // a satisfying block is found at the last block on the heap
                // if after using this block, the remaining memory is less than the size of a header, do not split
                if (nused + allocated_size + HEADER_SIZE >= segment_size) {
                    mark_used(cur, get_size(cur));
                } else {
                    // else split the last block into two
                    // creating a new free block at the end
                    mark_used(cur, allocated_size);
                    void * temp = get_next_header(cur);
                    mark_free(temp, segment_size - nused - allocated_size - HEADER_SIZE);
                    // update global variable
                    nblock++;
                    nused += (allocated_size + HEADER_SIZE);

                }

            }
            return get_payload(cur);
        }
        cur = get_next_header(cur);

    }
    return NULL;

}

void myfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    mark_free(get_header(ptr), get_size(get_header(ptr)));
}

void *myrealloc(void *old_ptr, size_t new_size) {
    if (old_ptr == NULL) {
        return mymalloc(new_size);
    }

    if (new_size == 0) {
        myfree(old_ptr);
        return NULL;
    }

    void * temp = mymalloc(new_size);
    if (!temp) {
        return NULL;
    }
    memcpy(temp, old_ptr, new_size);
    myfree(old_ptr);
    return temp;
}

bool validate_heap() {
    if (nused > segment_size) {
        printf("Oops! Have used more heap than total available?!\n");
        breakpoint();   // call this function to stop in gdb to poke around
        return false;
    }
    return true;

}

void dump_heap() {
    printf("Heap segment starts at address %p, ends at %p. %lu bytes currently used.", 
        segment_start, (char *)segment_start + segment_size, nused);
    for (int i = 0; i < nused; i++) {
        unsigned char *cur = (unsigned char *)segment_start + i;
        if (i % BYTES_PER_LINE == 0) {
            printf("\n%p: ", cur);
        }
        printf("%02x ", *cur);
    }
}
