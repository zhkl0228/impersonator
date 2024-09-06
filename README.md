# impersonator

impersonator is a fork of [BouncyCastle-bctls](https://github.com/bcgit/bc-java/commit/74a62440c93342a6743bb33c36a5ee224fc6c885) and [okhttp](https://github.com/square/okhttp/tree/parent-4.12.0) that is designed to impersonate TLS fingerprints.

`impersonator` can
impersonate browsers' TLS/JA3 and HTTP/2 fingerprints. If you are blocked by some
website for no obvious reason, you can give `impersonator` a try.

## Features
- Supports TLS/JA3/JA4 fingerprints impersonation.
- Supports HTTP/2 fingerprints impersonation.

## Usage

```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator</artifactId>
    <version>1.0.6</version>
</dependency>
```
- [src/test/java/com/github/zhkl0228/impersonator/IOSTest.java](https://github.com/zhkl0228/impersonator/blob/master/src/test/java/com/github/zhkl0228/impersonator/IOSTest.java)
```java
OkHttpClient client = ImpersonatorFactory.ios().newHttpClient();
```
