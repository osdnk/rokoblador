#include <stdlib.h>
#include <string.h>
#include "poly.h"
#include "polx.h"
#include "polz.h"
#include "fips202.h"
#include "labrador.h"
#include "chihuahua.h"
#include "dachshund.h"
#include "pack.h"
#include "rb_adapter.h"

void *rb_alloc_smplstmnt(void) {
  return calloc(1, sizeof(smplstmnt));
}

void *rb_alloc_witness(void) {
  return calloc(1, sizeof(witness));
}

void *rb_alloc_composite(void) {
  return calloc(1, sizeof(composite));
}

void *rb_alloc_commitment(void) {
  return calloc(1, sizeof(commitment));
}

void rb_free(void *p) {
  free(p);
}

void rb_smplstmnt_set_digest(void *stp, const uint8_t digest[16]) {
  memcpy(((smplstmnt *)stp)->h, digest, 16);
}

void rb_smplstmnt_add_constraint(void *stp, size_t ci, size_t nz, const size_t *idx,
                                  const size_t *off, const size_t *len,
                                  const int64_t *b, const int64_t *phi) {
  smplstmnt *st = stp;
  sparsecnst *cnst = &st->cnst[ci];
  size_t j, k, philen;
  polz t[1];
  __attribute__((aligned(16)))
  uint8_t hashbuf[N*QBYTES];
  shake128incctx shakectx;
  polx *buf;

  philen = 0;
  for(j = 0; j < nz; j++)
    philen += len[j];

  buf = init_sparsecnst_half(cnst, st->r, nz, philen, 1, 0, b == NULL);
  for(j = 0; j < nz; j++) {
    cnst->idx[j] = idx[j];
    cnst->off[j] = off[j];
    cnst->len[j] = len[j];
    cnst->mult[j] = 1;
    cnst->phi[j] = buf;
    buf += len[j];
  }
  cnst->a->len = 0;

  shake128_inc_init(&shakectx);
  shake128_inc_absorb(&shakectx, st->h, 16);

  if(b) {
    polzvec_fromint64vec(t, 1, 1, b);
    polzvec_topolxvec(cnst->b, t, 1);
    polzvec_bitpack(hashbuf, t, 1);
    shake128_inc_absorb(&shakectx, hashbuf, N*QBYTES);
  }

  for(j = 0; j < nz; j++) {
    for(k = 0; k < len[j]; k++) {
      polzvec_fromint64vec(t, 1, 1, phi);
      polzvec_topolxvec(&cnst->phi[j][k], t, 1);
      polzvec_bitpack(hashbuf, t, 1);
      shake128_inc_absorb(&shakectx, hashbuf, N*QBYTES);
      phi += N;
    }
  }

  shake128_inc_finalize(&shakectx);
  shake128_inc_squeeze(st->h, 16, &shakectx);
}

uint64_t rb_witness_normsq(void *wtp, size_t i) {
  return ((witness *)wtp)->normsq[i];
}

double rb_composite_size(void *cp) {
  return ((composite *)cp)->size;
}

uint64_t rb_compiled_q(void) {
  return ((uint64_t)1 << LOGQ) - QOFF;
}
