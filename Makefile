all: libmalloc.so test1 test2 test3 test4 test5 test6
.PHONY: all

test%: test%.c
	gcc -g -Wall -Werror $< -o $@

obj/:
	mkdir -p obj

obj/%.o: %.c %.h obj/
	gcc -fPIC -Wall -Werror -c $< -o $@

libmalloc.so: obj/malloc.o obj/memreq.o
	gcc -shared -Wl,-soname,$@ -o $@ obj/memreq.o obj/malloc.o

clean:
	rm -f obj/*.o test1 test2 test3 test4 test5 test6 libmalloc.so
.PHONY: clean

test:
	env LD_PRELOAD="./libmalloc.so" ./test$(TEST_CASE)
.PHONY: test

# test all:
# 	env LD_PRELOAD="./libmalloc.so" ./test1
# 	env LD_PRELOAD="./libmalloc.so" ./test2
# 	env LD_PRELOAD="./libmalloc.so" ./test3
# 	env LD_PRELOAD="./libmalloc.so" ./test4
# .PHONY: test all


