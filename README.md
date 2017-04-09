# PasswordPing Java Client Library

[![Build Status](https://travis-ci.org/passwordping/passwordping-java-client.svg?branch=master)](https://travis-ci.org/passwordping/passwordping-java-client)

## TOC

This README covers the following topics:

- [Installation](#installation)
	<!--- [Maven](#maven)
	- [Gradle](#gradle)
	- [Download](#download)-->
	- [Source](#source)
- [API Overview](#api-overview)
- [The PasswordPing constructor](#the-passwordping-constructor)
- [JavaDocs](#javadocs)

## Installation

The compiled library is available in two ways:

### Maven

The passwordping-java-client is available in Maven Central.

```xml
<dependencies>
    <dependency>
      <groupId>com.passwordping</groupId>
      <artifactId>passwordping-java-client</artifactId>
      <version>1.0.0</version>
    </dependency>
</dependencies>
```

### Gradle

```groovy
dependencies {
  compile 'com.passwordping:passwordping-java-client:1.0.0'
}
```

### Download

You can download a version of the `.jar` directly from <http://repo1.maven.org/maven2/com/passwordping/passwordping-java-client/>

### Source

You can build the project from the source in this repository.

## API Overview

Here's the API in a nutshell.

```java
// Create a new PasswordPing instance - this is our primary interface for making API calls
PasswordPing passwordping = new PasswordPing(YOUR_API_KEY, YOUR_API_SECRET);
 
// Check whether a password has been compromised
if (passwordping.CheckPassword("password-to-test")) {
    System.out.println("Password is compromised");
}
else {
    System.out.println("Password is not compromised");
}
 
// Check whether a specific set of credentials are compromised
if (passwordping.CheckCredentials("test@passwordping.com", "password-to-test")) {
    System.out.println("Credentials are compromised");
}
else {
    System.out.println("Credentials are not compromised");
}
 
// get all exposures for a given user
ExposuresResponse exposures = passwordping.GetExposuresForUser("test@passwordping.com");
System.out.println(exposures.getCount() + " exposures found for test@passwordping.com");
 
// now get the full details for the first exposure found
ExposureDetails details = passwordping.GetExposureDetails(exposures.getExposures()[0]);
System.out.println("First exposure for test@passwordping.com was " + details.getTitle());
```

More information in reference format can be found below.

## The PasswordPing constructor

The standard constructor takes the API key and secret you were issued on PasswordPing signup.

```java
PasswordPing passwordping = new PasswordPing(YOUR_API_KEY, YOUR_API_SECRET);
```

If you were instructed to use an alternate API endpoint, you may call the overloaded constructor and pass the base URL you were provided.

```java
PasswordPing passwordping = new PasswordPing(YOUR_API_KEY, YOUR_API_SECRET, "https://api-alt.passwordping.com/v1");
```

## JavaDocs

The JavaDocs contain more complete references for the API functions.  

They can be found here: <http://passwordping.github.com/passwordping-java-client/>
