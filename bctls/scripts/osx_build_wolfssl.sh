# https://github.com/wolfSSL/wolfssl
# ./configure --enable-jni --enable-static

JAVA_INC="$(realpath "$JAVA_HOME"/include)"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

"$(/usr/libexec/java_home -v 1.8)"/bin/javah -d ../src/test/native/wolfssl -cp ../target/classes \
  com.wolfssl.WolfSSL com.wolfssl.WolfSSLCertificate \
  com.wolfssl.wolfcrypt.ECC com.wolfssl.wolfcrypt.EccKey \
  com.wolfssl.wolfcrypt.RSA com.wolfssl.WolfSSLCertManager \
  com.wolfssl.WolfSSLCertRequest com.wolfssl.WolfSSLContext \
  com.wolfssl.WolfSSLSession com.wolfssl.WolfSSLX509Name \
  com.wolfssl.WolfSSLX509StoreCtx && \
  xcrun -sdk macosx clang -m64 -o libwolfssljni.dylib -dynamiclib -O3 \
  -framework CoreFoundation -framework Security \
  ../src/test/native/wolfssl/com_wolfssl_WolfSSL.c \
  ../src/test/native/wolfssl/com_wolfssl_WolfSSLSession.c \
  ../src/test/native/wolfssl/com_wolfssl_WolfSSLContext.c \
  ../src/test/native/wolfssl/com_wolfssl_wolfcrypt_RSA.c \
  ../src/test/native/wolfssl/com_wolfssl_wolfcrypt_ECC.c \
  ../src/test/native/wolfssl/com_wolfssl_wolfcrypt_EccKey.c \
  ../src/test/native/wolfssl/com_wolfssl_WolfSSLCertManager.c \
  ../src/test/native/wolfssl/com_wolfssl_WolfSSLCertRequest.c \
  ../src/test/native/wolfssl/com_wolfssl_WolfSSLCertificate.c \
  ../src/test/native/wolfssl/com_wolfssl_WolfSSLX509Name.c \
  ../src/test/native/wolfssl/com_wolfssl_WolfSSLX509StoreCtx.c \
  -I $HOME/git/wolfssl $HOME/git/wolfssl/src/.libs/libwolfssl.a \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" && \
  mv libwolfssljni.dylib ../src/test/resources/natives/osx_arm64/
