package com.enzoic.client;

import java.util.Date;

/**
 * The detailed information about a given credentials Exposure.
 */
public class ExposureDetails {

    /**
     * The ID of the Exposure
     * @return String
     */
    public String getId() {
        return id;
    }

    /**
     * Title of the exposure - for breaches, the domain of the origin site
     * @return String
     */
    public String getTitle() {
        return title;
    }

    /**
     * The number of credentials found in the exposure
     * @return long
     */
    public long getEntries() {
        return entries;
    }

    /**
     * The date the exposure occurred, as much as is known. The value is as follows:
     * null if the date is not known
     * Month and day set to December 31st, if only the year is known (e.g. "2015-12-31" if Exposure date was sometime in 2015)
     * Day set to the first of the month if only the month is known (e.g. "2015-06-01" if Exposure date was sometime in June 2015)
     * Otherwise, exact date if exact date is known, including time
     * @return Date
     */
    public Date getDate() {
        return date;
    }

    /**
     * A category for the origin website, if the exposure was a data breach.
     * @return String
     */
    public String getCategory() {
        return category;
    }

    /**
     * The format of the passwords in the Exposure, e.g. "Cleartext", "MD5", "BCrypt", etc.
     * @return String
     */
    public String getPasswordType() {
        return passwordType;
    }

    /**
     * The types of user data which were present in the Exposure, e.g. "Emails", "Passwords", "Physical Addresses", "Phone Numbers", etc.
     * @return String[]
     */
    public String[] getExposedData() {
        return exposedData;
    }

    /**
     * The date the Exposure was found and added to the Enzoic database.
     * @return Date
     */
    public Date getDateAdded() {
        return dateAdded;
    }

    /**
     * An array of URLs the data was found at. Only present for some types of Exposures, like when the source was a paste site.
     * @return String[]
     */
    public String[] getSourceURLs() {
        return sourceURLs;
    }

    /**
     * The number of unique email address domains in this Exposure. So, for instance, if the Exposure only contained "gmail.com" and "yahoo.com" email addresses, this number would be 2.
     * @return int
     */
    public int getDomainsAffected() {
        return domainsAffected;
    }

    private String id;
    private String title;
    private long entries;
    private Date date;
    private String category;
    private String passwordType;
    private String[] exposedData;
    private Date dateAdded;
    private String[] sourceURLs;
    private int domainsAffected;
}
