#include "site_read.h"

int read_site_db( char *dbname )
{
	Dbptr	dbstas;
	Dbptr	dbcalibration;
	Dbptr	dbinstrument;
	Dbptr	dbnetwork;
	Dbptr	dbschanloc;
	Dbptr	dbsensor;
	Dbptr	dbsite;
	Dbptr   dbsitechan;
	Dbptr	dbsnetsta;

	STACHAN *stachan, *checkstachan, *tstachan;
	long     nstachans;

	long	calibration_present;
	long     instrument_present;
	long	network_present;
	long	schanloc_present;
	long     sensor_present;
	long     site_present;
	long     sitechan_present;
	long     snetsta_present;
	char    net[10], sta[10], chan[10];
	long	i;
	void    *private = (void *) NULL;
        long     ns_stachan, ne_stachan;
        long     n;

        dbopen_database( dbname, "r", &dbstas );

	dbcalibration = dblookup( dbstas, 0, "calibration", 0, 0 );
        dbquery( dbcalibration, dbTABLE_PRESENT, &calibration_present );
        if( calibration_present == 0 )
        {
            die(0, " Can't find calibration database %s \n",dbname);
        }

	dbinstrument = dblookup( dbstas, 0, "instrument", 0, 0 );
        dbquery( dbinstrument, dbTABLE_PRESENT, &instrument_present );
        if( instrument_present == 0 )
        {
            printf(" Can't find instrument database %s \n",dbname);
        }

	dbnetwork = dblookup( dbstas, 0, "network", 0, 0 );
        dbquery( dbnetwork, dbTABLE_PRESENT, &network_present );
        if( network_present == 0 )
        {
            die(0, " Can't find network  database %s \n",dbname);
        }

	dbschanloc = dblookup( dbstas, 0, "schanloc", 0, 0 );
        dbquery( dbschanloc, dbTABLE_PRESENT, &schanloc_present );
        if( schanloc_present == 0 )
        {
            printf(" Can't find schanloc database %s \n",dbname);
        }

	dbsensor = dblookup( dbstas, 0, "sensor", 0, 0 );
        dbquery( dbsensor, dbTABLE_PRESENT, &sensor_present );
        if( sensor_present == 0 )
        {
            printf(" Can't find sensor database %s \n",dbname);
        }

        dbsite = dblookup( dbstas, 0, "site", 0, 0 );
        dbquery( dbsite, dbTABLE_PRESENT, &site_present );
	if( site_present == 0 )
        {
            die(0, " Can't find site database %s \n",dbname);
        }

        dbsitechan = dblookup( dbstas, 0, "sitechan", 0, 0 );
        dbquery( dbsitechan, dbTABLE_PRESENT, &sitechan_present );
	if( site_present == 0 )
        {
            die(0, " Can't find sitechan database %s \n",dbname);
        }

        dbsnetsta = dblookup( dbstas, 0, "snetsta", 0, 0 );
        dbquery( dbsnetsta, dbTABLE_PRESENT, &snetsta_present );
	if( snetsta_present == 0 )
        {
            printf(" Can't find snetsta database %s \n",dbname);
        }

        dbsite = dbsubset(dbsite, "offdate == NULL", 0 );
        dbsitechan = dbsubset(dbsitechan, "chan == \"HHZ\" || chan ==\"ELZ\" || chan == \"HGZ\" ", 0 );

        dbstas = dbjoin( dbsite, dbsitechan, 0, 0, 0, 0, 0 );
        dbstas = dbjoin( dbstas, dbsnetsta, 0, 0, 0, 0, 0 );

/*
        dbstas = dbsubset(dbstas, "site.offdate == NULL", 0 );
        dbstas = dbsubset(dbstas, "sitechan.chan == \"HHZ\" || sitechan.chan ==\"ELZ\" || sitechan.chan == \"HGZ\" ", 0 );
*/
        dbquery( dbstas, dbRECORD_COUNT, &nstachans );

	Stachans = newtbl(0);

        if(nstachans > 0)
        {
                for(dbstas.record = 0; dbstas.record<nstachans; dbstas.record++)
                {
			stachan = (STACHAN *) malloc( sizeof( STACHAN ) );
			init_stachan( stachan );

                        dbgetv(dbstas, 0, "snet", &stachan->net,
                                        "sta", &stachan->sta,
                                        "chan", &stachan->chan,
                                        0);
			pushtbl( Stachans, stachan);
                }
        }

	sorttbl( Stachans, cmp_sites_stachan, private );

	if(nstachans > 0)
        {
                for(dbstas.record = 0; dbstas.record<nstachans; dbstas.record++)
                {
                        checkstachan = (STACHAN *) malloc( sizeof( STACHAN ) );
                        init_stachan( checkstachan );

                        dbgetv(dbstas, 0, "snet", &checkstachan->net,
                                        "sta", &checkstachan->sta,
                                        "chan", &checkstachan->chan,
                                        0);
                        if( strncmp( checkstachan->chan, "HGZ", 3) == 0)
                        {
        			tstachan = (STACHAN *) malloc( sizeof( STACHAN ) );

                                tstachan = lookup_stachan(checkstachan->sta, "ELZ");
				if( tstachan == NULL ) tstachan = lookup_stachan(checkstachan->sta, "HHZ");

                                if( tstachan->net != NULL )
                                {
					searchtbl( (char *) &checkstachan, Stachans, cmp_sites_stachan, private, &ns_stachan, &ne_stachan );
                                        deltbl( Stachans, ns_stachan);
                                }
                         }
                }
        }
        dbclose( dbstas );
	sorttbl( Stachans, cmp_sites_stachan, private );
	return( maxtbl( Stachans ) );
}

void init_stachan( STACHAN *stachan )
{
	strcpy( stachan->net, "" );
	strcpy( stachan->sta, "" );
	strcpy( stachan->chan, "" );
	return;
}

STACHAN *lookup_stachan( char *sta, char *chan )
{
        STACHAN *stachan;
        long     ns_stachan, ne_stachan;
	void    *private = (void *) NULL;
        long     n;

        stachan = (STACHAN *) malloc( sizeof( STACHAN ) );
        strcpy( stachan->sta, sta );
        strcpy( stachan->chan, chan );
        n = searchtbl( (char *) &stachan, Stachans, cmp_sites_stachan, private, &ns_stachan, &ne_stachan );
        free( stachan );
        if( n != 1 )
        {
                return (STACHAN *) NULL;
        }
        else
        {
                stachan = gettbl( Stachans, ns_stachan );
                return stachan;
        }
}

static int cmp_sites_stachan( char *ap, char *bp, void *private )
{
        STACHAN **a, **b;

        a = (STACHAN **) ap;
        b = (STACHAN **) bp;
        if(strcmp((*a)->sta, (*b)->sta) > 0) return 1;
        else if(strcmp((*a)->sta, (*b)->sta) < 0) return -1;
        else
        {
                if(strcmp((*a)->chan, (*b)->chan) > 0) return 1;
                else if(strcmp((*a)->chan, (*b)->chan) < 0) return -1;
                else return 0;
        }
}
