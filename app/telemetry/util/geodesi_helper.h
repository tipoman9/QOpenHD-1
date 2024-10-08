#ifndef GEODESI_HELPER_H
#define GEODESI_HELPER_H

#include <geographiclib-c-2.0/src/geodesic.h>

// return: distance in m between 2 points
static double distance_between(double lat1,double lon1,double lat2,double lon2){
    double s12;
    //double azi1;
    //double azi2;

    geod_geodesic geod{};
    // from https://manpages.ubuntu.com/manpages/bionic/man3/geodesic.3.html
    const double a = 6378137, f = 1/298.257223563; /* WGS84 */
    geod_init(&geod,a,f);
    geod_inverse(&geod,lat1,lon1,lat2,lon2,&s12,0,0); //&azi1,&azi2
    return s12;
    /* todo: this could be easily extended to save the azimuth as well, which gives us the direction
           home for free as a result of the calculation above.
        */
}
#endif // GEODESI_HELPER_H
