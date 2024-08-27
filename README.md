# impersonator

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
    <version>1.0.5</version>
</dependency>
```
- [src/test/java/com/github/zhkl0228/impersonator/IOSTest.java](https://github.com/zhkl0228/impersonator/blob/master/src/test/java/com/github/zhkl0228/impersonator/IOSTest.java)
```java
OkHttpClient client = ImpersonatorFactory.ios().newHttpClient();
```
