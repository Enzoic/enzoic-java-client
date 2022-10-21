package com.enzoic.client;

/**
 * Response object for the Exposures API GET call
 */
public class ExposuresResponse {

    public ExposuresResponse() {
        count = 0;
        exposures = new String[0];
    }

    /**
     * The number of items in the exposures array
     * @return int
     */
    public int getCount() {
        return count;
    }

    /**
     * An array of Exposure IDs. The IDs can be used with the GetExposureDetails call to retrieve additional info on each exposure.
     * @return String[]
     */
    public String[] getExposures() {
        return exposures;
    }

    private int count;
    private String[] exposures;
}
