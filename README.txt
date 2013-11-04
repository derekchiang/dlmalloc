# README

This is an implementation of [Doug Lea's Malloc (dlmalloc)](http://en.wikipedia.org/wiki/C_dynamic_memory_allocation#dlmalloc).  I wrote it for my OS class, but it might be useful in the real world.  It improves upon [Doug Lea's original implementation](http://www.ivtools.org/ivtools/malloc.c) by supporting 64-bit machines.

[This article](http://g.oswego.edu/dl/html/malloc.html) explains the basic idea behind dlmalloc.

## Build

```bash
make
```