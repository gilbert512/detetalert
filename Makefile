BIN=detectalert

ldlibs= -lwffil -lassoc -lbrttpkt -lbrttfilter -lbrttutil $(ORBLIBS) -lpthread $(STOCKLIBS)

include $(ANTELOPEMAKE)  

DIRS=

OBJS=detectalert.o \
	site_read.o

detectalert : $(OBJS)
	$(CC) $(CFLAGS) -g -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

force:

