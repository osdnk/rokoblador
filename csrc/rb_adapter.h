#ifndef RB_ADAPTER_H
#define RB_ADAPTER_H

#include <stdint.h>
#include <stddef.h>

void *rb_alloc_smplstmnt(void);
void *rb_alloc_witness(void);
void *rb_alloc_composite(void);
void *rb_alloc_commitment(void);
void rb_free(void *p);

void rb_smplstmnt_set_digest(void *st, const uint8_t digest[16]);
void rb_smplstmnt_add_constraint(void *st, size_t ci, size_t nz, const size_t *idx,
                                  const size_t *off, const size_t *len,
                                  const int64_t *b, const int64_t *phi);

uint64_t rb_witness_normsq(void *wt, size_t i);
double rb_composite_size(void *composite);
uint64_t rb_compiled_q(void);

#endif
