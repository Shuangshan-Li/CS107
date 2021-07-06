#include "./allocator.h"
#include "./debug_break.h"
#include <stdio.h>
#include <string.h>

#define BYTES_PER_LINE 32


static void * segment_start;
static size_t segment_size;
// track how many blocks are on the heap
static size_t nblock;
// track how many bytes up to the last free block header are used
static size_t nused;

static Node * head = NULL;

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
    // nused tracks the bytes on our heap up to the first 8 byte (the header info) of our tail free block
    nused = HEADER_SIZE;
    // initialize
    head = segment_start;
    head->next = NULL;
    head->prev = NULL;
    mark_free(&(head->header), segment_size - NODE_SIZE);
    
    return true;
}

void *mymalloc(size_t requested_size) {
    if (requested_size == 0) {
        return NULL;
    }
    // allocated_size must be aligned with 16 instead of 8 because we are using
    // the first 16 bytes to store pointers in free blocks. Otherwise segmentation fault
    // will occur
    size_t allocated_size = roundup(requested_size, ALIGNMENT_1);
    Node * cur = head;
    // search for a satisfying free block on the linked list
    while (cur) {
        // found on satisfying free block
        if (is_free(&cur->header) && get_size(&cur->header) >= allocated_size) {
            // if this block is not at the end of our currently used memory space aka the last free block.
            if ((char*)get_payload(&cur->header) != (char*)segment_start + nused) {
                // simply return this free block.
                mark_used(&cur->header, get_size(&cur->header));
                if (cur->prev) {
                    cur->prev->next = cur->next;
                }
                if (cur->next) {
                  cur->next->prev = cur->prev; 
                }
                if (cur == head) {
                    head = cur->next;
                }
                return get_payload(&cur->header);
            } else {
                // else we need to split the last free block into one that we return and another new free block
                mark_used(&cur->header, allocated_size);
                
                // put the last new free block at the head of the linked list
                Node * temp = get_next_header(&cur->header);
                
                temp->next = head;
                temp->prev = NULL;
                if (head) {
                    head->prev = temp;    
                }
                head = temp;
                // remove the free block that we will return from the linked list
                if (cur->prev) {
                    cur->prev->next = cur->next;
                }
                if (cur->next) {
                    cur->next->prev = cur->prev;
                }

                mark_free(&temp->header, segment_size - nused - allocated_size - HEADER_SIZE);
                // update global info
                nblock++;
                nused += (allocated_size + HEADER_SIZE);
                return get_payload(&cur->header);
            }
        }
        cur = cur->next;
    }

    return NULL;

}

void myfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    Node * temp = get_header(ptr);
    mark_free(&temp->header, get_size(&temp->header));
    temp->prev = NULL;
    temp->next = head;
    if (head) {
        head->prev = temp;
    }
    head = temp;


    // coalescing
    Node * adjacent_node = get_next_header(&temp->header);
    if (is_free(&adjacent_node->header)) {
        if (adjacent_node->prev) {
            adjacent_node->prev->next = adjacent_node->next;
        }
        if (adjacent_node->next) {
            adjacent_node->next->prev = adjacent_node->prev;
        }

        nblock--;
        // if the coalesced free block is the tail one, update nused
        if ((char *)&adjacent_node->header == (char *)segment_start + nused - HEADER_SIZE) {
            nused = nused - HEADER_SIZE - get_size(&temp->header);
        }
        mark_free(&temp->header, get_size(&temp->header) + HEADER_SIZE + get_size(&adjacent_node->header));
    }
}

void *myrealloc(void *old_ptr, size_t new_size) {

    if (old_ptr == NULL) {
        return mymalloc(new_size);
    }
    if (new_size == 0) {
        myfree(old_ptr);
        return NULL;
    }


    Node * temp = get_header(old_ptr);
    size_t old_size = get_size(&temp->header);
    new_size = roundup(new_size, ALIGNMENT_1);         
    // scenario 1: shrink -> split and add one more free block
    if (new_size < old_size && old_size - new_size >= ALIGNMENT_1 + HEADER_SIZE) {
        mark_used(&temp->header, new_size);
        Node * new_free_block = get_next_header(&temp->header);
        mark_free(&new_free_block->header, old_size - new_size - HEADER_SIZE);
        new_free_block->prev = NULL;
        new_free_block->next = head;
        if (head) {
            head->prev = new_free_block;
        }
        head = new_free_block;
        nblock++;
        return get_payload(&temp->header);
    }

    // scenario 2: grow but within padding -> do nothing(keep using this block)
    if (new_size <= old_size) {
        return get_payload(&temp->header);
    }
       // scenario 3: grow out of padding but have enough adjacent free blocks -> coalesce
    if (new_size > old_size) {
        Node * adjacent_node = get_next_header(&temp->header);
        size_t accumulative_size = old_size;
        // keep searching to the right to find enough free adjacent blocks for coalescing
        while ((char*)&adjacent_node->header <= (char*)segment_start + segment_size && is_free(&adjacent_node->header)) {
            accumulative_size += HEADER_SIZE + get_size(&adjacent_node->header);
            // if the are enough free adjacent blocks for coalescing
            if (accumulative_size >= new_size) {
                Node * cur = get_next_header(&temp->header);
                // coalescing
                while (old_size < accumulative_size && old_size < new_size) {
                    // if the block we absorb is not the tail free block
                    if ((char *)&cur->header != (char *)segment_start + nused - HEADER_SIZE) {
                        
                        if (cur->prev) {
                            cur->prev->next = cur->next;
                        }
                        if (cur->next) {
                            cur->next->prev = cur->prev;
                        }
                        if (head == cur) {
                            head = cur->next;
                        }
                        mark_used(&temp->header, get_size(&temp->header) + HEADER_SIZE + get_size(&cur->header));
                        old_size += HEADER_SIZE + get_size(&cur->header);

                        cur = get_next_header(&cur->header);
                    } else {
                        // if the block we absorb is the tail free block -> split
                        size_t aligned_size = roundup(new_size - old_size, ALIGNMENT_1);
                        Node * new_tail = (Node *)((char*)cur + aligned_size);
                        new_tail->prev = NULL;
                        new_tail->next = NULL;
                        Node * cached_prev = cur->prev;
                        Node * cached_next = cur->next;

                        if (cached_prev) {
                            cached_prev->next = new_tail;
                            new_tail->prev = cached_prev;
                        }

                        if (cached_next) {
                            cached_next->prev = new_tail;
                            new_tail->next = cached_next;
                        }

                        if (head == cur) {
                            head = new_tail;
                        }

                        mark_used(&temp->header, old_size + aligned_size);
                        nused += aligned_size;
                        old_size += aligned_size;
                        mark_free(&new_tail->header, segment_size - nused);

                    }

                }
                return get_payload(&temp->header);
            }
            adjacent_node = get_next_header(&adjacent_node->header);
        }
    // scenario 4: grow out of padding and not enough adjacent free blocks -> move to new place
        void * new_location = mymalloc(new_size);
        if (!new_location) {
            return NULL;
        }
        memcpy(new_location, old_ptr, old_size);
        myfree(old_ptr);
        return new_location;


    }
    return NULL;

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
