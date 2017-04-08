package com.passwordping.client;

/**
 * Response object for the Exposures API GET call
 */
public class ExposuresResponse {

    public ExposuresResponse() {
        count = 0;
        exposures = new String[0];
    }

    /**
     * @return The number of items in the exposures array
     */
    public int getCount() {
        return count;
    }

    /**
     * @return An array of Exposure IDs. The IDs can be used with the GetExposureDetails call to retrieve additional info on each exposure.
     */
    public String[] getExposures() {
        return exposures;
    }

    private int count;
    private String[] exposures;
}
