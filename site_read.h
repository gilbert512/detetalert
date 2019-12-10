#ifndef SITE_READ_H
#define SITE_READ_H

#include "Pkt.h"
#include "db.h"
#include "stock.h"

#define STREQ(a, b) (strcmp((a), (b)) == 0)

typedef struct {
	char    net[PKT_NAMESIZE];
        char    sta[PKT_NAMESIZE];
        char    chan[PKT_NAMESIZE];
} STACHAN;

Tbl *Stachans;

void init_stachan( STACHAN *stachan );
int read_site_db( char * );
STACHAN *lookup_stachan( char *sta, char *chan );
static int cmp_sites_stachan( char *ap, char *bp, void *private );

#endif
