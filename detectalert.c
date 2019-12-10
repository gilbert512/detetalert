// Modified by Gilbert. 2017.06.22
// for Simulation
// Changed compare with now & origin time
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "brttpkt.h"
#include "brttfilter.h"
#include "brttutil.h"
#include "Pkt.h"
#include "site_read.h"

#define DEFAULT_PFFILE "./pf/detectalert"
#define DEFAULT_DIALOG "./pf/message"
#define MONITOR_STAINFO_NUM 100
#define WAIT_STAINFO_NUM 1000

#ifndef TRUE
  #define TRUE  1
#endif
#ifndef FALSE
  #define FALSE 0
#endif
#ifndef HN_STA_COUNT
  #define HN_STA_COUNT 3
#endif
#ifndef HN_ON
  #define HN_ON   1
#endif
#ifndef HN_SAME
  #define HN_SAME 2
#endif
#ifndef HN_OFF
  #define HN_OFF  0
#endif

#include <errno.h>

static char *Version = "     1.0      " ;


static pthread_t main_thread;
//static int myshutdown = 0;

Pf   *get_pf=0;

Tbl *monitor_tbl;
Tbl *wait_tbl;
int monitor_cnt, wait_cnt;
double wait_second;
int view_alert;

int setDetectInfo(const char *ac_pcSta, const int ac_iState);

typedef struct StaInfo
{
    char m_sSta[10];
    double m_dTime;
}StaInfo;

typedef struct StaInfo2
{
    char m_sSta[10];
    int m_iState;
}StaInfo2;


static void usage()
{
    cbanner ("$Date: 2017/10/13 12:00:49 $",
            "[-p detectalert] [-d popupdialog][-r reject] [-v] orb dbname",
            "","","");
    exit (1);
}

static void startup_banner()
{
    long i, n;
    char *pre1 = "******";
    char *pre2 = "*     ";
    char *post1 = "******";
    char *post2 = "     *";
    char line1[256], line2[256];

    n = strlen(Version);
    strcpy (line1, "*");
    for (i=1; i<n; i++) {
        strcat (line1, "*");
    }

    elog_notify (0, "\n");
    elog_notify (0, "%s%s%s\n", pre1, line1, post1);
    strcpy (line2, " ");
    for (i=1; i<n; i++) {
        strcat (line2, " ");
    }
    memcpy (line2, "detectalert", strlen("detectalert"));
    elog_notify (0, "%s%s%s\n", pre2, line2, post2);
    elog_notify (0, "%s%s%s\n", pre2, Version, post2);
    elog_notify (0, "%s%s%s\n", pre1, line1, post1);

}

myusleep (double sec)
{
    struct timespec ts;

    ts.tv_sec = (unsigned int)sec;
    ts.tv_nsec = (unsigned int)((sec - (double) ts.tv_sec) * 1.e9 + 0.5);
    nanosleep (&ts, NULL);
    //sleep(sec);

    return (0);
}

int main (int argc, char **argv)
{
    int         verbose = 0 ;
    double      time ;
    char       *orbname=0, *dbname=0, *s, *pf=0, *dialog=0;
    int         c,
            errflg = 0;
    int         orb, i, j ;
    int         pktid ;    
    double      end_time ;
    char        srcname[ORBSRCNAME_SIZE] ;
    double      after = 0.0, quit = 0.0  ;    
    char       *match = 0, *reject = 0 ;
    int         nmatch ;
    char       *packet=0 ;
    int         nbytes = 0 ;
    int         retcode, type;
    int         bufsize=0 ;
    int         abort = 0 ;    
    char        sta[10], tmp_sta[10], chan[10], state[10];
    double      dettime;    
    char        *tmpstr;
    char        wk_msg[120];
    int sleepev;
    int get;
    OrbreapThr *event_thr=NULL;
    int         numsite;
    STACHAN    *stachan;

    Program_Name = argv[0];
    elog_init ( argc, argv );

    startup_banner();        

    while ((c = getopt (argc, argv, "m:p:d:r:S:Vv")) != -1)
        switch (c) {

            case 'm':
                match = optarg ;
                break ;

            case 'p':
                pf = (optarg) ;
                break ;

            case 'r':
                reject = optarg ;
                break ;

            case 'V':
                usage ();
                break;

            case 'v':
                verbose++ ;
                break ;

            case 'd':
                dialog = (optarg) ;
                break;


            case '?':
                errflg++;
        }

    if (errflg || (argc-optind < 1 || argc-optind > 4))
        usage ();

    orbname = argv[optind++];  
    dbname  = argv[optind++];

    if ( argc > optind ) {
        after = str2epoch ( argv[optind++] ) ;
        if ( argc > optind ) {
            quit = str2epoch ( argv[optind++] ) ;
            if ( quit < after )
                quit += after ;
        }
    }

    /* orb setup stuff */

    if ( (orb = orbopen ( orbname, "r&" )) < 0 )
        die ( 0, "Can't open ring buffer '%s'\n", orbname ) ;

    if ( match ) {
        if ( (nmatch = orbselect ( orb, match )) < 0 )
            complain ( 1, "orbselect '%s' failed\n", match ) ;
        else
            printf ( "%d sources selected after select\n", nmatch) ;
    }

    if ( reject ) {
        if ( (nmatch = orbreject ( orb, reject )) < 0 )
            complain ( 1, "orbreject '%s' failed\n", match ) ;
        else
            printf ( "%d sources selected after reject\n", nmatch) ;
    }

    if ( after > 0 ) {
        if ((pktid = orbafter ( orb, after )) < 0) {
            complain ( 1, "orbafter to %s failed\n", s=strtime(after) )  ;
            free(s) ;
            pktid = orbtell ( orb ) ;
            printf ("pktid is still #%d\n", pktid ) ;
        } else
            printf ("new starting pktid is #%d\n", pktid ) ;
    }

    elog_notify(0,"starting at %s\n", epoch2str(now() + (float)9.*3600, "%Y%m%d%H%M%S.%s") ) ;

    /* Read detectalert parameter file */
    if(dialog == NULL) dialog = DEFAULT_DIALOG;
    if(pf == NULL )  pf=DEFAULT_PFFILE;
    if (pfread(pf, &get_pf) != 0)
    {
        die(1, "Pf read error.\n");
    }

    monitor_tbl = pfget_tbl(get_pf, "MONITOR_STA");
    monitor_cnt = maxtbl(monitor_tbl);
    if( verbose )
        elog_notify(0,"monitor sta count : %i\n", monitor_cnt ) ;

    for (i = 0; i < monitor_cnt; i++)
    {
        tmpstr = (char *) gettbl(monitor_tbl, i);
        elog_notify(0,"monitor sta[%d]: %s\n", i, tmpstr) ;
    }

    wait_tbl = pfget_tbl(get_pf, "WAIT_STA");
    wait_cnt = maxtbl(wait_tbl);

    if( verbose )
        elog_notify(0,"wait sta count : %i\n", wait_cnt ) ;

     for (i = 0; i < wait_cnt; i++)
    {
        tmpstr = (char *) gettbl(wait_tbl, i);
        elog_notify(0,"wait sta[%d]: %s\n", i, tmpstr) ;
    }

    if( monitor_cnt <=0 && wait_cnt <=0 )
    {
        die(1, " can't found monitor_sta and wait_sta in pf file\n");
    }

    //wait_second = 5.0;
    //view_alert = 3;
    wait_second = pfget_double(get_pf, "WAIT_SECONDS");
    view_alert = pfget_int(get_pf, "VIEW_ALERT");

     if( verbose )
        elog_notify(0,"wait_second : %f, view_alert : %d", wait_second, view_alert ) ;

    /* setup array*/
    StaInfo monitor_sInfo[MONITOR_STAINFO_NUM];
    for(i=0; i<MONITOR_STAINFO_NUM; i++) 
    {
        strcpy(monitor_sInfo[i].m_sSta, "");        
        monitor_sInfo[i].m_dTime = -999;
    }

    StaInfo wait_sInfo[WAIT_STAINFO_NUM];
    for(i=0; i<WAIT_STAINFO_NUM; i++) 
    {
        strcpy(wait_sInfo[i].m_sSta, "");        
        wait_sInfo[i].m_dTime = -999;
    }

    StaInfo tmp_sInfo[view_alert];
    for(i=0; i<view_alert; i++) 
    {
        strcpy(tmp_sInfo[i].m_sSta, "");        
        tmp_sInfo[i].m_dTime = -999;
    }

    stachan = (STACHAN *) malloc( sizeof( STACHAN ) );

    if( (numsite=read_site_db(dbname)) <= 0)
    {
        fprintf(stderr,"can't read site_chan from database\n");
        exit(1);
    }
    else
    {
        elog_notify(0,"reading the station of %i from database  \n", numsite);        
    }

    main_thread = pthread_self ();


    elog_notify(0, "Setting complete.... \n");
    sleepev = 0;
    get = 1;   
    double curr_time = now(); 

    while ( ! abort )
    {        
        if (sleepev) myusleep (0.1);        
        // elimite old data (monitor array)
        curr_time = now();
        // elimite old data (compare array)
        for (i=0; i<WAIT_STAINFO_NUM; i++) 
        {
            if(wait_sInfo[i].m_dTime == -999)
                continue;

             if ( fabs(wait_sInfo[i].m_dTime - curr_time) > wait_second * 2.)            
            {
                elog_notify(0, "elimite old wait array data %s, %f", wait_sInfo[i].m_sSta, wait_sInfo[i].m_dTime);
                strcpy(wait_sInfo[i].m_sSta, "");
                wait_sInfo[i].m_dTime = -999;
            }
        }

        int cnt = 0;
        for (i=0; i<MONITOR_STAINFO_NUM; i++) 
        {            
            if(monitor_sInfo[i].m_dTime == -999)
                continue;

            //clear temp
            for(int tp=0; tp<view_alert; tp++) 
            {                        
                strcpy(tmp_sInfo[tp].m_sSta, "");
                tmp_sInfo[tp].m_dTime = -999;
            }
            cnt = 0;

            // find compare array
            for (j=0; j<WAIT_STAINFO_NUM; j++)                           
            {
                if ( fabs(monitor_sInfo[i].m_dTime - wait_sInfo[j].m_dTime) <= wait_second) 
                {
                    int checks = 0;
                    // check same detection in temp
                    for(int tp = 0; tp < view_alert; tp++)
                    {
                        if(strcmp(wait_sInfo[j].m_sSta, tmp_sInfo[tp].m_sSta) == 0)
                            checks = 1;
                    }

                    if(!checks)
                    {
                        for(int tp = 0; tp < view_alert; tp++)
                        {
                            if ( tmp_sInfo[tp].m_dTime == -999) // write detection in temp
                            {
                                strcpy(tmp_sInfo[tp].m_sSta, wait_sInfo[j].m_sSta);                            
                                tmp_sInfo[tp].m_dTime = wait_sInfo[j].m_dTime;                                
                                cnt++;                                                        
                                break;
                            }
                        }
                    } 
                } 
                if(cnt >= view_alert)
                    break;                        
            }

            if(cnt >= view_alert)
            {
                // popup alert                
                sprintf(wk_msg, "awish %s &", dialog);
                elog_notify(0, "called alert popup (%s)", wk_msg);
                system(wk_msg);                                    

                strcpy(monitor_sInfo[i].m_sSta, "");
                monitor_sInfo[i].m_dTime = -999;
                continue;
            }
            if ( fabs(monitor_sInfo[i].m_dTime - curr_time) > wait_second)     // over limit time                     
            {
                elog_notify(0, "elimite old monitor array data %s, %f", monitor_sInfo[i].m_sSta, monitor_sInfo[i].m_dTime);
                strcpy(monitor_sInfo[i].m_sSta, "");
                monitor_sInfo[i].m_dTime = -999;
            }            
        }


        if (get) {
            orbget ( orb, ORBCURRENT, &pktid, srcname, &time, &packet, &nbytes, &bufsize ) ;
            get = 0;
            orbseek (orb, ORBCURRENT);
        } 
        else {
            if (event_thr == NULL) {
                event_thr = orbreapthr_new (orb, 0.0, 5);
                if (event_thr == NULL) {
                    die (0, "orbreapthr_new() error for main event reap thread.\n");
                }
            }
            retcode = orbreapthr_get (event_thr, &pktid, srcname, &time, &packet, &nbytes, &bufsize);
            if (retcode < 0) {
                complain ( 1, "\norbreap fails\n" ) ;
                break ;
            }
            switch (retcode) {
            case ORBREAPTHR_STOPPED:
                die (0, "fatal orbreapthr_get()  main event reap thread stopped.\n");
            case ORBREAPTHR_NODATA:                
                sleepev = 1;
                break;
            default:
                sleepev = 0;
                break; 
            }
        }   

        if(sleepev) continue;

        if ( strncmp (srcname, "/db/detection", 13) == 0 )
        {  
            type = -1;                        
            Packet *unstuffed=0 ;
            type = unstuffPkt (srcname, time, packet, nbytes, &unstuffed);            
            if(type < 0)
            {
                complain(0, "error unstuff process.");
                continue;
            }
           
            dbgetv( unstuffed->db, 0, "sta", sta, 0);
            dbgetv( unstuffed->db, 0, "chan", chan, 0);
            dbgetv( unstuffed->db, 0, "time", &dettime, 0);
            dbgetv( unstuffed->db, 0, "state", state, 0);
            
            stachan = lookup_stachan( &sta[0], &chan[0] );
            if( stachan->net == NULL ) continue;

            if( strncmp(state,"l", 1) ==0 )
            {      
                int iState = setDetectInfo(sta, HN_ON);
                if ( iState != HN_ON)
                {
                    // HN_SAME or error
                    //elog_notify(0, "%s[%d]setDetectInfo(%s, %d) = %d(%s)   dettime:%.lf\n",
                    //        __func__, __LINE__, sta, HN_ON, iState, strerror(errno), dettime);
                    continue;
                }           
                // compare monitor sta
                for(i = 0; i < monitor_cnt; i++)
                {
                    tmpstr = (char *) gettbl(monitor_tbl, i);
                    sscanf(tmpstr,"%s", tmp_sta);                    
                    if(strcmp(tmp_sta, sta) == 0)
                    {                        
                        for (j=0; j<MONITOR_STAINFO_NUM; j++)
                        {
                            if ( monitor_sInfo[j].m_dTime == -999 )
                            {
                                strcpy(monitor_sInfo[j].m_sSta, sta);                            
                                //monitor_sInfo[j].m_dTime = dettime;
                                monitor_sInfo[j].m_dTime = now();
                                if(verbose)
                                    elog_notify(0,"add monitor array : %s\n", sta) ;
                                break;
                            }                            
                        }
                        break;
                    }
                }

                // compare wait sta
                for(i = 0; i < wait_cnt; i++)
                {
                    tmpstr = (char *) gettbl( wait_tbl, i);
                    sscanf(tmpstr,"%s", tmp_sta);
                    if(strcmp(tmp_sta, sta) == 0)
                    {                        
                        for (j=0; j<WAIT_STAINFO_NUM; j++)
                        {
                            if ( wait_sInfo[j].m_dTime == -999 )
                            {
                                strcpy(wait_sInfo[j].m_sSta, sta);                            
                                //wait_sInfo[j].m_dTime = dettime;
                                wait_sInfo[j].m_dTime = now();
                                if(verbose)
                                    elog_notify(0,"add wait array : %s\n", sta) ;
                                break;
                            }                            
                        }
                        break;
                    }
                }
            }
        }
    }
    free(packet) ;
    end_time = now() + (float)9.*3600 ;
    elog_notify(0,"finished at %s\n", epoch2str(end_time, "%Y%m%d%H%M%S.%s"));
    return 0 ;
}

int setDetectInfo(const char *ac_pcSta, const int ac_iState)
{
    static StaInfo2 *s_pstStaInfo;
    static int s_iStaCount = 0;

    int iMemSize;
    int iIndex;
    int iState = HN_SAME;
    int iOldState = HN_OFF;

    if ((ac_pcSta == NULL) || ((ac_iState != HN_OFF) && (ac_iState != HN_ON)))
    {
        errno = EINVAL;
        return -1;
    }

    if (s_iStaCount == 0)
    {
        iMemSize = HN_STA_COUNT * sizeof(StaInfo);
        s_pstStaInfo = (StaInfo *)malloc(iMemSize);
        if (s_pstStaInfo == NULL)
        {
            return -1;
        }
        s_iStaCount = HN_STA_COUNT;
        memset(s_pstStaInfo, 0, iMemSize);
    }

    for (iIndex = 0; iIndex < s_iStaCount; iIndex++)
    {
        if (strlen(s_pstStaInfo[iIndex].m_sSta) == 0)
        {
#if 0
            elog_notify(0, "%s[%d]add station()\n", __func__, __LINE__);
#endif

            // m_sSta? ª˜¾ÄÂãþÈ ùåÁî ??
            strcpy(s_pstStaInfo[iIndex].m_sSta, ac_pcSta);
            s_pstStaInfo[iIndex].m_iState = HN_OFF;
            iOldState = HN_OFF;
            break;
        }
        if (strcmp(s_pstStaInfo[iIndex].m_sSta, ac_pcSta) == 0)
        {
            iOldState = s_pstStaInfo[iIndex].m_iState;
            break;
        }
    }

    if (iIndex == s_iStaCount)
    {
        //elog_notify(0, "%s[%d]realloc()\n", __func__, __LINE__);

        // s_iStaCount ¬ ?ùöÞÓ ùåÁî s_iStaCount ¬ þ® ½ùì Ã•Ã—ùêÃ±ª  ¬ ³Ä¹ð.
        iMemSize = sizeof(StaInfo) * (s_iStaCount + HN_STA_COUNT);
        s_pstStaInfo = (StaInfo *)realloc(s_pstStaInfo, iMemSize);
        if (s_pstStaInfo == NULL)
        {
            return -1;
        }
        memset(&s_pstStaInfo[s_iStaCount], 0, sizeof(StaInfo) * HN_STA_COUNT);
        s_iStaCount += HN_STA_COUNT;

        strcpy(s_pstStaInfo[iIndex].m_sSta, ac_pcSta);
        s_pstStaInfo[iIndex].m_iState = HN_OFF;
        iOldState = HN_OFF;
    }

    if (iOldState == ac_iState)
    {
        iState = HN_SAME;
    }
    else
    {
        iState = ac_iState;
        s_pstStaInfo[iIndex].m_iState = ac_iState;
    }

    return iState;
}
