#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <setjmp.h>
#include "poly.h"
#include "polx.h"
#include "polz.h"
#include "fips202.h"
#include "labrador.h"
#include "chihuahua.h"
#include "dachshund.h"
#include "pack.h"
#include "rokoblador.h"

#define STMT_MAGIC 0x524B424Cu
#define WIT_MAGIC 0x524B4257u
#define FORMAT_VERSION 2u
#define WITNESS_COEFF_MAX 23170
#define MAX_R ((size_t)1 << 20)
#define MAX_K ((size_t)1 << 24)
#define MAX_N ((size_t)1 << 24)

static jmp_buf die_jmp;

static void die(const char *fmt, ...) {
  va_list ap;

  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  va_end(ap);
  fputc('\n',stderr);
  longjmp(die_jmp,1);
}

static void xread(FILE *f, void *buf, size_t sz, const char *what) {
  if(fread(buf,1,sz,f) != sz)
    die("ERROR: failed to read %s",what);
}

static uint32_t read_u32(FILE *f, const char *what) {
  uint32_t v;

  xread(f,&v,sizeof(v),what);
  return v;
}

static uint64_t read_u64(FILE *f, const char *what) {
  uint64_t v;

  xread(f,&v,sizeof(v),what);
  return v;
}

typedef struct {
  uint8_t digest[16];
  size_t r;
  size_t k;
  uint64_t betasq_w_total;
  uint64_t betasq_inner_total;
  size_t *n;
  uint64_t *betasq;
} stmt_head;

static void parse_stmt_header(FILE *f, stmt_head *h) {
  uint32_t magic,version,role,flags;
  uint64_t q,n_i,betasq_i,sum_w,sum_inner;
  size_t i;
  const uint64_t compiled_q = ((uint64_t)1 << LOGQ) - QOFF;

  magic = read_u32(f,"statement magic");
  if(magic != STMT_MAGIC)
    die("ERROR: statement.bin bad magic 0x%08X (expected 0x%08X)",magic,STMT_MAGIC);
  version = read_u32(f,"statement version");
  if(version != FORMAT_VERSION)
    die("ERROR: statement.bin unsupported version %u (expected %u)",version,FORMAT_VERSION);
  q = read_u64(f,"statement q");
  if(q != compiled_q)
    die("ERROR: statement.bin q = %llu does not match compiled modulus %llu",
        (unsigned long long)q,(unsigned long long)compiled_q);

  xread(f,h->digest,sizeof(h->digest),"statement digest");
  h->r = (size_t)read_u64(f,"statement r");
  h->k = (size_t)read_u64(f,"statement k");
  if(!h->r || h->r > MAX_R)
    die("ERROR: statement.bin r = %zu out of sane range",h->r);
  if(!h->k || h->k > MAX_K)
    die("ERROR: statement.bin k = %zu out of sane range",h->k);
  h->betasq_w_total = read_u64(f,"betasq_w_total");
  h->betasq_inner_total = read_u64(f,"betasq_inner_total");

  h->n = malloc(h->r*sizeof(size_t));
  h->betasq = malloc(h->r*sizeof(uint64_t));
  if(!h->n || !h->betasq)
    die("ERROR: out of memory allocating statement vector arrays (r = %zu)",h->r);

  sum_w = 0;
  sum_inner = 0;
  for(i=0;i<h->r;i++) {
    n_i = read_u64(f,"vector n_i");
    betasq_i = read_u64(f,"vector betasq_i");
    role = read_u32(f,"vector role");
    flags = read_u32(f,"vector flags");
    if(!n_i || n_i > MAX_N)
      die("ERROR: statement.bin vector %zu rank %llu out of sane range",i,(unsigned long long)n_i);
    h->n[i] = (size_t)n_i;
    h->betasq[i] = betasq_i;
    if(role == 0)
      sum_w += betasq_i;
    if(flags & 1u)
      sum_inner += betasq_i;
  }
  if(sum_w > h->betasq_w_total)
    die("ERROR: statement.bin sum betasq over role-0 vectors (%llu) exceeds betasq_w_total (%llu)",
        (unsigned long long)sum_w,(unsigned long long)h->betasq_w_total);
  if(sum_inner > h->betasq_inner_total)
    die("ERROR: statement.bin sum betasq over INNER-flagged vectors (%llu) exceeds betasq_inner_total (%llu)",
        (unsigned long long)sum_inner,(unsigned long long)h->betasq_inner_total);
}

static void parse_and_build_witness(const char *path, witness *wt, const stmt_head *h) {
  FILE *f;
  uint32_t magic,version;
  uint64_t q,r,n_i;
  size_t i,j;
  const uint64_t compiled_q = ((uint64_t)1 << LOGQ) - QOFF;
  int64_t *coeffs;

  f = fopen(path,"rb");
  if(!f)
    die("ERROR: cannot open witness file %s",path);

  magic = read_u32(f,"witness magic");
  if(magic != WIT_MAGIC)
    die("ERROR: witness.bin bad magic 0x%08X (expected 0x%08X)",magic,WIT_MAGIC);
  version = read_u32(f,"witness version");
  if(version != FORMAT_VERSION)
    die("ERROR: witness.bin unsupported version %u (expected %u)",version,FORMAT_VERSION);
  q = read_u64(f,"witness q");
  if(q != compiled_q)
    die("ERROR: witness.bin q = %llu does not match compiled modulus %llu",
        (unsigned long long)q,(unsigned long long)compiled_q);
  r = read_u64(f,"witness r");
  if((size_t)r != h->r)
    die("ERROR: witness.bin r = %llu does not match statement r = %zu",(unsigned long long)r,h->r);

  init_witness_raw(wt,h->r,h->n);

  for(i=0;i<h->r;i++) {
    n_i = read_u64(f,"witness vector n_i");
    if((size_t)n_i != h->n[i])
      die("ERROR: witness.bin vector %zu rank %llu does not match statement rank %zu",
          i,(unsigned long long)n_i,h->n[i]);

    coeffs = malloc(h->n[i]*N*sizeof(int64_t));
    if(!coeffs)
      die("ERROR: out of memory allocating witness vector %zu (n = %zu)",i,h->n[i]);
    xread(f,coeffs,h->n[i]*N*sizeof(int64_t),"witness coefficients");

    for(j=0;j<h->n[i]*N;j++)
      if(coeffs[j] < -WITNESS_COEFF_MAX || coeffs[j] > WITNESS_COEFF_MAX)
        die("ERROR: witness vector %zu coefficient %zu = %lld out of hard range +-%d",
            i,j,(long long)coeffs[j],WITNESS_COEFF_MAX);

    if(set_witness_vector_raw(wt,i,h->n[i],1,coeffs))
      die("ERROR: set_witness_vector_raw failed for vector %zu",i);
    free(coeffs);

    if(wt->normsq[i] > h->betasq[i])
      die("ERROR: witness vector %zu recomputed normsq %llu exceeds statement betasq %llu",
          i,(unsigned long long)wt->normsq[i],(unsigned long long)h->betasq[i]);
  }

  fclose(f);
}

static void set_sparsecnst_manual(sparsecnst *cnst, uint8_t h[16], size_t nz,
                                  const size_t len[], const int64_t *phi, const int64_t *b)
{
  size_t j,k;
  polz t[1];
  __attribute__((aligned(16)))
  uint8_t hashbuf[N*QBYTES];
  shake128incctx shakectx;

  cnst->a->len = 0;

  shake128_inc_init(&shakectx);
  shake128_inc_absorb(&shakectx,h,16);

  if(b) {
    polzvec_fromint64vec(t,1,1,b);
    polzvec_topolxvec(cnst->b,t,1);
    polzvec_bitpack(hashbuf,t,1);
    shake128_inc_absorb(&shakectx,hashbuf,N*QBYTES);
  }

  for(j=0;j<nz;j++) {
    for(k=0;k<len[j];k++) {
      polzvec_fromint64vec(t,1,1,phi);
      polzvec_topolxvec(&cnst->phi[j][k],t,1);
      polzvec_bitpack(hashbuf,t,1);
      shake128_inc_absorb(&shakectx,hashbuf,N*QBYTES);
      phi += N;
    }
  }

  shake128_inc_finalize(&shakectx);
  shake128_inc_squeeze(h,16,&shakectx);
}

static void build_smplstmnt(FILE *f, smplstmnt *st, const stmt_head *h) {
  size_t i,j,nz,philen;
  size_t *idx,*off,*len;
  uint64_t v,has_b;
  int64_t b[N];
  int64_t *bptr;
  int64_t *phi;
  sparsecnst *cnst;
  polx *buf;

  if(init_smplstmnt_raw(st,h->r,h->n,h->betasq,h->k))
    die("ERROR: init_smplstmnt_raw failed");
  memcpy(st->h,h->digest,sizeof(st->h));

  for(i=0;i<h->k;i++) {
    nz = (size_t)read_u64(f,"constraint nz");
    if(!nz || nz > 64)
      die("ERROR: constraint %zu has insane nz = %zu",i,nz);

    idx = malloc(nz*sizeof(size_t));
    off = malloc(nz*sizeof(size_t));
    len = malloc(nz*sizeof(size_t));
    if(!idx || !off || !len)
      die("ERROR: out of memory allocating constraint %zu block arrays (nz = %zu)",i,nz);

    philen = 0;
    for(j=0;j<nz;j++) {
      v = read_u64(f,"constraint idx");
      if(v >= h->r)
        die("ERROR: constraint %zu block %zu idx = %llu out of range [0,%zu)",i,j,(unsigned long long)v,h->r);
      if(j && (size_t)v < idx[j-1])
        die("ERROR: constraint %zu block %zu idx not monotone non-decreasing",i,j);
      idx[j] = (size_t)v;

      v = read_u64(f,"constraint off");
      off[j] = (size_t)v;
      if(j && idx[j] == idx[j-1] && off[j] <= off[j-1])
        die("ERROR: constraint %zu block %zu offset not strictly increasing for repeated idx %zu",i,j,idx[j]);

      v = read_u64(f,"constraint len");
      len[j] = (size_t)v;
      if(off[j] > h->n[idx[j]] || len[j] > h->n[idx[j]] - off[j])
        die("ERROR: constraint %zu block %zu off (%zu) + len (%zu) exceeds vector %zu rank %zu",
            i,j,off[j],len[j],idx[j],h->n[idx[j]]);

      philen += len[j];
    }

    has_b = read_u64(f,"constraint has_b");
    if(has_b != 0 && has_b != 1)
      die("ERROR: constraint %zu has_b = %llu neither 0 nor 1",i,(unsigned long long)has_b);
    if(has_b) {
      xread(f,b,sizeof(b),"constraint b");
      bptr = b;
    }
    else
      bptr = NULL;

    phi = malloc(philen*N*sizeof(int64_t));
    if(!phi)
      die("ERROR: out of memory allocating constraint %zu phi (len = %zu)",i,philen);
    xread(f,phi,philen*N*sizeof(int64_t),"constraint phi");

    cnst = &st->cnst[i];
    buf = init_sparsecnst_half(cnst,h->r,nz,philen,1,0,has_b == 0);
    for(j=0;j<nz;j++) {
      cnst->idx[j] = idx[j];
      cnst->off[j] = off[j];
      cnst->len[j] = len[j];
      cnst->mult[j] = 1;
      cnst->phi[j] = buf;
      buf += len[j];
    }
    set_sparsecnst_manual(cnst,st->h,nz,len,phi,bptr);

    free(idx);
    free(off);
    free(len);
    free(phi);
  }
}

static double elapsed(struct timespec *t0, struct timespec *t1) {
  return (double)(t1->tv_sec-t0->tv_sec) + (double)(t1->tv_nsec-t0->tv_nsec)*1e-9;
}

int rokoblador_run(const char *statement_path, const char *witness_path, double *pack_kb_out) {
  stmt_head h = {};
  witness wt = {};
  smplstmnt st = {};
  commitment com = {};
  composite p = {};
  FILE *fstmt;
  struct timespec t0,t1;
  int ret;

  if(setjmp(die_jmp)) {
    free_comkey();
    return 1;
  }

  fstmt = fopen(statement_path,"rb");
  if(!fstmt)
    die("ERROR: cannot open statement file %s",statement_path);

  parse_stmt_header(fstmt,&h);
  parse_and_build_witness(witness_path,&wt,&h);
  build_smplstmnt(fstmt,&st,&h);
  fclose(fstmt);
  free(h.n);
  free(h.betasq);

  print_smplstmnt_pp(&st);

  ret = simple_verify(&st,&wt);
  if(ret) {
    fprintf(stderr,"ROKOBLADOR simple_verify: FAIL (code %d)",ret);
    if(ret >= 10)
      fprintf(stderr," -- constraint index %d failed",ret-10);
    fputc('\n',stderr);
    free_smplstmnt(&st);
    free_witness(&wt);
    free_comkey();
    return 1;
  }
  printf("ROKOBLADOR simple_verify: OK\n");

  clock_gettime(CLOCK_MONOTONIC,&t0);
  ret = composite_prove_simple(&p,&com,&st,&wt);
  clock_gettime(CLOCK_MONOTONIC,&t1);
  if(ret) {
    fprintf(stderr,"ROKOBLADOR composite_prove: FAIL (code %d)\n",ret);
    free_commitment(&com);
    free_smplstmnt(&st);
    free_witness(&wt);
    free_comkey();
    return 1;
  }
  printf("ROKOBLADOR composite_prove: OK (%.2fs)\n",elapsed(&t0,&t1));

  clock_gettime(CLOCK_MONOTONIC,&t0);
  ret = composite_verify_simple(&p,&com,&st);
  clock_gettime(CLOCK_MONOTONIC,&t1);
  if(ret) {
    fprintf(stderr,"ROKOBLADOR composite_verify: FAIL (code %d)\n",ret);
    free_composite(&p);
    free_commitment(&com);
    free_smplstmnt(&st);
    free_witness(&wt);
    free_comkey();
    return 1;
  }
  printf("ROKOBLADOR composite_verify: OK (%.2fs)\n",elapsed(&t0,&t1));

  *pack_kb_out = p.size;

  free_composite(&p);
  free_commitment(&com);
  free_smplstmnt(&st);
  free_witness(&wt);
  free_comkey();
  return 0;
}
