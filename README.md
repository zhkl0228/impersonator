# impersonator

impersonator is a fork of [BouncyCastle-bctls](https://github.com/bcgit/bc-java/commit/74a62440c93342a6743bb33c36a5ee224fc6c885) and [okhttp](https://github.com/square/okhttp/tree/parent-4.12.0) that is designed to impersonate TLS fingerprints.

`impersonator` can
impersonate browsers' TLS/JA3 and HTTP/2 fingerprints. If you are blocked by some
website for no obvious reason, you can give `impersonator` a try.

## Features
- Supports TLS/JA3/JA4 fingerprints impersonation.
- Supports HTTP/2 fingerprints impersonation.

## Usage

TLS/JA3/JA4 fingerprints impersonation
```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator-bctls</artifactId>
    <version>1.0.8</version>
</dependency>
```

TLS/JA3/JA4 fingerprints and HTTP/2 fingerprints impersonation
```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator-okhttp</artifactId>
    <version>1.0.8</version>
</dependency>
```
- [src/test/java/com/github/zhkl0228/impersonator/IOSTest.java](https://github.com/zhkl0228/impersonator/blob/master/src/test/java/com/github/zhkl0228/impersonator/IOSTest.java)
```java
ImpersonatorApi api = ImpersonatorFactory.ios();
SSLContext context = api.newSSLContext(null, null); // for TLS/JA3/JA4 fingerprints impersonation

OkHttpClientFactory factory = OkHttpClientFactory.create(api);
OkHttpClient client = factory.newHttpClient(); // for TLS/JA3/JA4 fingerprints and HTTP/2 fingerprints impersonation
```
