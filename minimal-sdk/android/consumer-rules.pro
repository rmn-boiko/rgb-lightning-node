# Consumer R8/ProGuard rules for the UTEXO minimal SDK.
#
# Only what R8 must not strip or rename: the JNA entry points the generated
# uniffi bindings rely on through reflection. Everything else in
# com.utexo.minimalsdk is ordinary Kotlin and may be shrunk and obfuscated by
# the consumer like any other library code. Deliberately NO blanket
# `-keep class com.utexo.minimalsdk.** { *; }`.

# The `UniffiLib : Library` interface: JNA binds each method by NAME to a
# symbol exported from libutexo_minimal_sdk.so, so the names must survive.
-keep interface * extends com.sun.jna.Library { *; }
# JNA Structures (RustBuffer, ForeignBytes, UniffiRustCallStatus, ...) are
# laid out from their declared field names and order. The order comes from
# the runtime-retained @Structure.FieldOrder annotation, which JNA reads
# reflectively; R8 drops it unless the attribute is kept, and then every FFI
# call fails with "Structure.getFieldOrder() ... does not provide enough names".
-keep class * extends com.sun.jna.Structure { *; }
-keepattributes RuntimeVisibleAnnotations
-keep class * extends com.sun.jna.ptr.ByReference { *; }
# Foreign-trait callbacks (HttpTransport) are invoked from Rust through a
# JNA Callback whose single `callback` method JNA finds reflectively.
-keep class * implements com.sun.jna.Callback { *; }
-keep class * extends com.sun.jna.Callback { *; }
# JNA's own runtime is loaded reflectively (Native, Structure, ...).
-keep class com.sun.jna.** { *; }
# JNA references java.awt (absent on Android); silence the missing-class warning.
-dontwarn java.awt.**
