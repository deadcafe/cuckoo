CFLAGS  = -g -O3 -Werror -Wextra -Wall -Wstrict-aliasing -std=gnu99 -m64 -pipe -march=native

CPPFLAGS = -c -I. -D_GNU_SOURCE
LIBS =
LDFLAGS =

#CFLAGS += -funroll-loops -frerun-loop-opt
#CFLAGS += -fforce-addr

SRCS	=		\
	cuckoo.c	\
	idx_queue.c	\
	hashmap.c	\
	main.c

OBJS = ${SRCS:.c=.o}
DEPENDS = .depend

TARGET = cuckoo

.SUFFIXES:      .o .c
.PHONY: all clean depend

all	:	depend $(TARGET)

.c.o	:
	$(CC) $(CFLAGS) $(CPPFLAGS) $<

$(TARGET):	$(OBJS)
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

$(OBJS)	:	Makefile

clean:
	rm -f $(OBJS) $(TARGET) $(DEPENDS) *~ core core.*

depend:	$(SRCS) Makefile
	-@ $(CC) $(CPPFLAGS) -MM -MG $(SRCS) > $(DEPENDS)

-include $(DEPENDS)
