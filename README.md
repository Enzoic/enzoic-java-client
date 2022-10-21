# Enzoic Java Client Library

[![Build Status](https://travis-ci.org/Enzoic/enzoic-java-client.svg?branch=master)](https://travis-ci.org/Enzoic/enzoic-java-client)

## TOC

This README covers the following topics:

- [Installation](#installation)
	<!--- [Maven](#maven)
	- [Gradle](#gradle)
	- [Download](#download)-->
	- [Source](#source)
- [API Overview](#api-overview)
- [The Enzoic constructor](#the-enzoic-constructor)
- [JavaDocs](#javadocs)

## Installation

The compiled library is available in two ways:

### Maven

The enzoic-java-client is available in Maven Central.

```xml
<dependencies>
    <dependency>
      <groupId>com.enzoic</groupId>
      <artifactId>enzoic-java-client</artifactId>
      <version>3.4.0</version>
    </dependency>
</dependencies>
```

### Gradle

```groovy
dependencies {
  compile 'com.enzoic:enzoic-java-client:3.4.0'
}
```

### Download

You can download a version of the `.jar` directly from <https://oss.sonatype.org/content/groups/public/com/enzoic/enzoic-java-client/>

### Source

You can build the project from the source in this repository.

## API Overview

Here's the API in a nutshell.

```java
// Create a new Enzoic instance - this is our primary interface for making API calls
Enzoic enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET);

// (Optional) Set a reasonable timeout for our application, in milliseconds.
enzoic.SetRequestTimeout(500);

// Check whether a password has been compromised
if (enzoic.CheckPassword("password-to-test")) {
    System.out.println("Password is compromised");
}
else {
    System.out.println("Password is not compromised");
}

// Check whether a password has been compromised with extended return information
CheckPasswordExResponse response = enzoic.CheckPasswordEx("password-to-test");
if (response != null) {
    System.out.println("Password is compromised");
    if (response.isRevealedInExposure()) {
        System.out.println("Password has been revealed in a data breach " +
            Integer.toString(response.exposureCount()) +  
            " times and has a relative breach frequency of " +
            Integer.toString(response.relativeExposureFrequency()));
    }
    else {
        System.out.println("Password has not been revealed in a data breach, but exists publicly in cracking dictionaies.");
    }
}
else {
    System.out.println("Password is not compromised");
}

 
// Check whether a specific set of credentials are compromised
if (enzoic.CheckCredentials("test@enzoic.com", "password-to-test")) {
    System.out.println("Credentials are compromised");
}
else {
    System.out.println("Credentials are not compromised");
}

// Use the CheckCredentialsEx call to tweak performance by including the
// date/time of the last check and excluding BCrypt
if (enzoic.CheckCredentialsEx("test@enzoic.com", "password-to-test",
        lastCheckTimestamp, new PasswordType[] { PasswordType.BCrypt })) {
    System.out.println("Credentials are compromised");
}
else {
    System.out.println("Credentials are not compromised");
}
 
// get all exposures for a given user
ExposuresResponse exposures = enzoic.GetExposuresForUser("test@enzoic.com");
System.out.println(exposures.getCount() + " exposures found for test@enzoic.com");
 
// now get the full details for the first exposure found
ExposureDetails details = enzoic.GetExposureDetails(exposures.getExposures()[0]);
System.out.println("First exposure for test@enzoic.com was " + details.getTitle());

// get all passwords for a given user - requires special approval, contact Enzoic sales
UserPasswords userPasswords = enzoic.GetUserPasswords("eicar_0@enzoic.com");
System.out.println("First password for eicar_0@enzoic.com was " + userPasswords.getPasswords[0].getPassword());
```

More information in reference format can be found below.

## The Enzoic constructor

The standard constructor takes the API key and secret you were issued on Enzoic signup.

```java
Enzoic enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET);
```

If you were instructed to use an alternate API endpoint, you may call the overloaded constructor and pass the base URL you were provided.

```java
Enzoic enzoic = new Enzoic(YOUR_API_KEY, YOUR_API_SECRET, "https://api-alt.enzoic.com/v1");
```

## JavaDocs

The JavaDocs contain more complete references for the API functions.  

They can be found here: <http://javadoc.io/doc/com.enzoic/enzoic-java-client/>
