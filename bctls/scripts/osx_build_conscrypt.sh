# https://github.com/google/boringssl

JAVA_INC="$(realpath "$JAVA_HOME"/include)"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

xcrun -sdk macosx clang -std=c++17 -o ../target/generate_constants \
  -I $HOME/git/boringssl/include \
  ../src/test/native/conscrypt/gen/cpp/generate_constants.cc && \
  ../target/generate_constants > ../src/main/java/org/conscrypt/NativeConstants.java && \
  xcrun -sdk macosx clang -m64 -std=c++17 -o libconscrypt_openjdk_jni-osx-aarch_64.dylib -dynamiclib -O3 \
  -fvisibility=hidden -lstdc++ \
  ../src/test/native/conscrypt/jni/main/cpp/conscrypt/*.cc \
  -I ../src/test/native/conscrypt/jni/main/include \
  -I ../src/test/native/conscrypt/jni/unbundled/include \
  -I $HOME/git/boringssl/include \
  $HOME/git/boringssl/build.arm/libcrypto.a \
  $HOME/git/boringssl/build.arm/libssl.a \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" && \
  mv libconscrypt_openjdk_jni-osx-aarch_64.dylib ../src/test/resources/META-INF/native/
