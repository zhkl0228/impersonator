# impersonator

`impersonator` can
impersonate browsers' TLS/JA3 fingerprints. If you are blocked by some
website for no obvious reason, you can give `impersonator` a try.

## Features
- Supports JA3/TLS fingerprints impersonation.

## Usage
```java
        <dependency>
            <groupId>com.github.zhkl0228</groupId>
            <artifactId>impersonator</artifactId>
            <version>1.0.0</version>
        </dependency>

SSLContext context = ImpersonatorFactory.ios(null, new TrustManager[]{DefaultTrustManager.INSTANCE})

```
