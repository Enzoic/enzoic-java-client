package com.enzoic.client;

/**
 * Specifies a hash algorithm type for a password
 */
enum ExposureDataType {
    Emails (0),
    Passwords (1),
    Usernames (2),
    CreditCardInfo (3),
    PhysicalAddresses (4),
    PhoneNumbers (5),
    IPAddresses (6),
    DOBs (7),
    Genders (8),
    Names (9),
    WebsiteActivity (10),
    SecurityQuestionsAndAnswers (11),
    PrivateCommunications (12),
    PaymentHistories (13),
    BankingAccountInformation (14),
    GovernmentIssuedIDNumbers (15),
    MaritalStatus (16),
    EmploymentInformation (17),
    SexualPreferences (18),
    SocialConnections (19),
    Education (20),
    DrinkingAndDrugUsage (21),
    DeviceInformation (22);
    
    private int numVal;

    ExposureDataType(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }
}
