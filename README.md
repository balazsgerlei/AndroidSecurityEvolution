# AndroidSecurityEvolution

Significant security enchancements of recent major Android versions, starting with Android 5.0 Lollipop (API 21).

## Android 5.0 (API 21) - Lollipop

[Security Enhancements in Android 5.0](https://source.android.com/docs/security/enhancements/enhancements50)

* Starting August 2023, _Google Play Services_ updates will only be received from this Android version see [https://android-developers.googleblog.com/2023/07/google-play-services-discontinuing-updates-for-kitkat.html](https://android-developers.googleblog.com/2023/07/google-play-services-discontinuing-updates-for-kitkat.html)
* [Full Disk Encryption (FDE)](https://source.android.com/docs/security/features/encryption/full-disk) by default (manufacturers can still opt out)
* SELinux fully enforced
* `WebView` is a separate package

## Android 6 (API 23) - Marshmallow

[Security Enhancements in Android 6.0](https://source.android.com/docs/security/enhancements/enhancements60)

* [Keystore](https://developer.android.com/reference/java/security/KeyStore) API significantly extended (symmetric cryptographic primitives, AES and HMAC support and access control system for hardware-backed keys) see [https://source.android.com/docs/security/features/keystore](https://source.android.com/docs/security/features/keystore)
* [TEE](https://source.android.com/docs/security/features/trusty) is a requirement
* New API ([isInsideSecureHardware](https://developer.android.com/reference/android/security/keystore/KeyInfo#isInsideSecureHardware())) for checking whether a KeyStore key is stored in _secure hardware_ (e.g., [Trusted Execution Environment (TEE)](https://source.android.com/docs/security/features/trusty) or Secure Element (SE))
* Apps need to request permissions at runtime see [https://developer.android.com/about/versions/marshmallow/android-6.0-changes#behavior-runtime-permissions](https://developer.android.com/about/versions/marshmallow/android-6.0-changes#behavior-runtime-permissions) and [https://developer.android.com/training/permissions/requesting](https://developer.android.com/training/permissions/requesting)
* More restrictive [SELinux](https://source.android.com/docs/security/features/selinux) (IOCTL filtering, tightening of SELinux domains, etc.) see [https://source.android.com/docs/security/features/selinux](https://source.android.com/docs/security/features/selinux)

## Android 7 (API 24) - Nougat

[Security Enhancements in Android 7.0](https://source.android.com/docs/security/enhancements/enhancements70)

* Separate User and System Certificate Trust Store, meaning Man-in-the-Middle attacks basically require root access from this point, see [https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html](https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html)
* Added [Network Security Config](https://developer.android.com/training/articles/security-config) support so apps can customize the behavior of their secure (HTTPS, TLS) connections in a simple declarative way, without code modification. It supports custom trust anchors (which [Certificate Authorities (CA)](https://en.wikipedia.org/wiki/Certificate_authority) the app trusts), debug-only overrides, cleartext traffic opt-out and certificate pinning (limiting which server keys are trusted), see [https://developer.android.com/about/versions/nougat/android-7.0#network_security_config](https://developer.android.com/about/versions/nougat/android-7.0#network_security_config)
* By default apps targeting Android 7.0 only trust system-provided certificates and no longer trust user-added [Certificate Authorities (CA)](https://en.wikipedia.org/wiki/Certificate_authority), even without custom [Network Security Config](https://developer.android.com/training/articles/security-config), see [https://developer.android.com/about/versions/nougat/android-7.0#default_trusted_ca](https://developer.android.com/about/versions/nougat/android-7.0#default_trusted_ca)
* Update to _Keymaster 2_ with support for [Key Attestation](https://source.android.com/docs/security/features/keystore/attestation) and version binding (preventing rolling back to an unsecure old version without losing keys), see [https://developer.android.com/about/versions/nougat/android-7.0#key_attestation](https://developer.android.com/about/versions/nougat/android-7.0#key_attestation) and [https://source.android.com/docs/security/features/keystore/implementer-ref](https://source.android.com/docs/security/features/keystore/implementer-ref) and [https://developer.android.com/training/articles/security-key-attestation](https://developer.android.com/training/articles/security-key-attestation)
* [File Based Encryption (FBE)](https://source.android.com/docs/security/features/encryption/file-based) introduced, but it's optional to implement by manufacturers, see [https://developer.android.com/about/versions/nougat/android-7.0#direct_boot](https://developer.android.com/about/versions/nougat/android-7.0#direct_boot) and [https://developer.android.com/training/articles/direct-boot](https://developer.android.com/training/articles/direct-boot)
* Updated [SELinux](https://source.android.com/docs/security/features/selinux) configuration: further locking fown application sandbox, breaking up mediaserver stack into smaller processes with reduced permissios (mitigation against Stagefright), see [https://source.android.com/docs/security/features/selinux](https://source.android.com/docs/security/features/selinux)

## Android 8 (API 26) - Oreo

[Security Enhancements in Android 8.0](https://source.android.com/docs/security/enhancements/enhancements80)

* JavaScript evaluation runs in a separate process in `WebView` so JavaScript code cannot access the app's memory so easily, see [https://android-developers.googleblog.com/2017/06/whats-new-in-webview-security.html](https://android-developers.googleblog.com/2017/06/whats-new-in-webview-security.html)
* `WebView` respects [Network Security Config](https://developer.android.com/training/articles/security-config) and `cleartextTrafficPermitted` flag (on older Android version it loads HTTP sites even if clear text traffic should not be allowed by the config), see [https://developer.android.com/about/versions/oreo/android-8.0-changes#o-sec](https://developer.android.com/about/versions/oreo/android-8.0-changes#o-sec)
* [Safe Browsing API](https://developer.android.com/develop/ui/views/layout/webapps/managing-webview#safe-browsing) added to `WebView`, see [https://developer.android.com/about/versions/oreo/android-8.0#wv](https://developer.android.com/about/versions/oreo/android-8.0#wv) so users would be warned when trying to navigating to a potentially unsafe website (verified by [Google Safe Browsing](https://developers.google.com/safe-browsing/)) if enabled
* `FLAG_SECURE` `Window` flag is supported more and disallows taking screenshots of the screen where this is set.
* Update to _Keymaster 3_ with C++ HAL (instead of a C one), addition of HIDL and ID attestation support, see [https://source.android.com/docs/security/features/keystore](https://source.android.com/docs/security/features/keystore) and [https://source.android.com/docs/security/features/keystore/implementer-ref](https://source.android.com/docs/security/features/keystore/implementer-ref)
* Project Treble introduced (only devices released with this version support project Treble, the ones updated will not get it), separating lower-level vendor code from Android system framework and enabling easier security update delivery, see [https://android-developers.googleblog.com/2020/12/treble-plus-one-equals-four.html](https://android-developers.googleblog.com/2020/12/treble-plus-one-equals-four.html)
* Updated [SELinux](https://source.android.com/docs/security/features/selinux) to work with Treble. SELinux policy allows manufacturers and SOC vendors to update their parts of the policy independently from the platform and vice versa, see [https://source.android.com/docs/security/features/selinux](https://source.android.com/docs/security/features/selinux)
* Further hardening media stack: mobild Hardware Abstraction Layers (HALs) from running in a shared process to running in their own sandboxed processes.

## Android 9 (API 28) - Pie

[Security Enhancements in Android 9](https://source.android.com/docs/security/enhancements/enhancements9)
[Android 9 release notes - Security Features](https://source.android.com/docs/setup/about/p-release-notes#security_features)

* Cleartext network traffic (HTTP) disabled by default, apps need to explicitly set `cleartextTrafficPermitted` to `true` in their [Network Security Config](https://developer.android.com/training/articles/security-config) it if they still want to use it (not recommended), see [https://developer.android.com/about/versions/pie/android-9.0-changes-28#tls-enabled](https://developer.android.com/about/versions/pie/android-9.0-changes-28#tls-enabled) and [https://nphausg.medium.com/android-8-cleartext-http-traffic-not-permitted-73c1c9e3b803](https://nphausg.medium.com/android-8-cleartext-http-traffic-not-permitted-73c1c9e3b803)
* Update to _Keymaster 4_ with support for 3DES encryption and secure key import, see [https://source.android.com/docs/security/features/keystore](https://source.android.com/docs/security/features/keystore) and [https://source.android.com/docs/security/features/keystore/implementer-ref](https://source.android.com/docs/security/features/keystore/implementer-ref)
* Added support for embedded [Secure Element (SE)](https://source.android.com/docs/compatibility/cts/secure-element), see [https://source.android.com/docs/setup/about/p-release-notes#secure_element_se_service](https://source.android.com/docs/setup/about/p-release-notes#secure_element_se_service)
* Reading contents of the Clipboard in the background requires special permission
* Disk Encryption (can be either Full Disk Encryption or File Based Encryption) is mandatory for all devices (shipping with this version)
* `BiometricPrompt` introduced standardizing the UI that is shown during biometric authentication and providing a better API to apps that is harder to misuse

## Android 10 (API 29) - Quince Tart

[Security Enhancements in Android 10](https://source.android.com/docs/security/enhancements/enhancements10)
[Android 10 release notes](https://source.android.com/docs/setup/about/android-10-release)

* File access disabled by default in `WebView`
* TLS 1.3 enabled by default
* Certificates signed with SHA-1 no longer trusted in TLS
* System overlay permissions are reset on reboot for apps downloaded from Google Play, and after 30 seconds for sideloaded apps.
* Background apps cannot launch other Activites (e.g. other apps)
* File Based Encryption (FBE) is mandatory for devices that launch with this Android version (devices updated to it can still continue using Full Disk Encryption)
* `FLAG_SECURE` flag is added for biometric or device credential (PIN, pattern or password) prompts, including unlocking the device and `BiometricPrompt` in apps. This means you cannot make a screenshot of these screens and they appear black in screen shares.
* StrandHogg 2.0 exploit no longer possible

## Android 11 (API 30) - Red Velvet Cake

[Security Enhancements in Android 11](https://source.android.com/docs/security/enhancements/enhancements11)
[Android 11 release notes](https://source.android.com/docs/setup/about/android-11-release)

* Task Hijacking (StrandHogg 1.0) exploit no longer possible
* Apps cannot query information about other installed apps by default
* Permissions auto-reset for unused apps

## Android 12 (API 31) - Snow Cone

[Android 12 release notes](https://source.android.com/docs/setup/about/android-12-release)

* Exported flag needs to be defined explicitly in Manifests for components with Intent Filters
* Generic web intents resolve to user's default browser app unless the target app is approved for the specific domain contained in that web Intent
* Replace many BouncyCastle implementations of cryptographic algorithms with Conscrypt ones
* The user gets notified if an app accesses Clipboard data of another app for the first time
* Apps can no longer close System Dialogs
* Tapjacking mitigation: Apps are prevented from consuming touch events where an overlay obscures the app
* Scoped Storage always enforced, opting out of it via `requestLegacyExternalStorage` is no longer possible

## Android 13 (API 33) - Tiramisu

[Android 13 release notes](https://source.android.com/docs/setup/about/android-13-release)

* Non-matching Intents are blocked by Intent filters (apps cannot send an Intent to another app's exported component unless it fully matches the Intent filter defined by it)
* Only File Based Encryption (FBE) is allowed, Full Disk Encryption is no longer - not even for devices updated from a version that it was allowed
