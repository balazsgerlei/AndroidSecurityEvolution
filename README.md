# Android Security Evolution

Significant security enhancements of recent major Android versions, starting with _Android 5.0 Lollipop_ (API 21).

## Android 5.0 (API 21) - Lollipop

[Security Enhancements in Android 5.0](https://source.android.com/docs/security/enhancements/enhancements50)

* Starting August 2023, _Google Play Services_ updates will only be received from this Android version see [Google Play services discontinuing updates for KitKat (API levels 19 & 20) starting August 2023](https://android-developers.googleblog.com/2023/07/google-play-services-discontinuing-updates-for-kitkat.html)
* [Full Disk Encryption (FDE)](https://source.android.com/docs/security/features/encryption/full-disk) by default (manufacturers can still opt out), see [Encryption](https://source.android.com/docs/security/features/encryption) and [Security Enhancements in Android 5.0](https://source.android.com/docs/security/enhancements/enhancements50)
* [SELinux](https://source.android.com/docs/security/features/selinux) fully enforced, see [Security Enhancements in Android 5.0](https://source.android.com/docs/security/enhancements/enhancements50)
* `WebView` is a separate package, see [Security Enhancements in Android 5.0](https://source.android.com/docs/security/enhancements/enhancements50) and [The Updatable WebView on Android 5.0 Lollipop What Is It and Why Should You Care?](https://infinum.com/blog/the-updateable-webview-on-android-5-lollipop-what-is-it-and-why-should-you-care/)

## Android 6 (API 23) - Marshmallow

[Security Enhancements in Android 6.0](https://source.android.com/docs/security/enhancements/enhancements60)

* [Keystore](https://developer.android.com/reference/java/security/KeyStore) API significantly extended (symmetric cryptographic primitives, _AES_ and _HMAC_ support and access control system for hardware-backed keys) see [Hardware-backed Keystore](https://source.android.com/docs/security/features/keystore)
* [TEE](https://source.android.com/docs/security/features/trusty) is a requirement, see [Hardware-backed Keystore](https://source.android.com/docs/security/features/keystore) and [7.3.10. Fingerprint Sensor section of Android 6.0 Compatibility Definition](https://source.android.com/docs/compatibility/6.0/android-6.0-cdd#7_3_10_fingeprint)
* New API (`isInsideSecureHardware`) for checking whether a [KeyStore](https://developer.android.com/training/articles/keystore) key is stored in _secure hardware_ (e.g., [Trusted Execution Environment (TEE)](https://source.android.com/docs/security/features/trusty) or Secure Element (SE)), see [isInsideSecureHardware method of KeyInfo](https://developer.android.com/reference/android/security/keystore/KeyInfo#isInsideSecureHardware())
* Apps need to request permissions at runtime see [Runtime Permissions section of Android 6.0 Changes](https://developer.android.com/about/versions/marshmallow/android-6.0-changes#behavior-runtime-permissions) and [Request runtime permissions
](https://developer.android.com/training/permissions/requesting) and [Security Enhancements in Android 6.0](https://source.android.com/docs/security/enhancements/enhancements60)
* More restrictive [SELinux](https://source.android.com/docs/security/features/selinux) (_IOCTL filtering_, tightening of _SELinux_ domains, etc.) see [Security-Enhanced Linux in Android](https://source.android.com/docs/security/features/selinux) and [Security Enhancements in Android 6.0](https://source.android.com/docs/security/enhancements/enhancements60)

## Android 7 (API 24) - Nougat

[Security Enhancements in Android 7.0](https://source.android.com/docs/security/enhancements/enhancements70)

* Separate _User_ and _System Certificate Trust Store_, meaning _Man-in-the-Middle_ attacks basically require root access from this point, see [Changes to Trusted Certificate Authorities in Android Nougat](https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html)
* Added [Network Security Config](https://developer.android.com/training/articles/security-config) support so apps can customize the behavior of their secure (_HTTPS_, _TLS_) connections in a simple declarative way, without code modification. It supports custom trust anchors (which [Certificate Authorities (CA)](https://en.wikipedia.org/wiki/Certificate_authority) the app trusts), debug-only overrides, _cleartext traffic_ opt-out and certificate pinning (limiting which server keys are trusted), see [Network Security Config section of Android 7.0 for Developers
](https://developer.android.com/about/versions/nougat/android-7.0#network_security_config)
* By default apps targeting _Android 7.0_ only trust system-provided certificates and no longer trust user-added [Certificate Authorities (CA)](https://en.wikipedia.org/wiki/Certificate_authority), even without custom [Network Security Config](https://developer.android.com/training/articles/security-config), see [Default Trusted Certificate Authority of Android 7.0 for Developers](https://developer.android.com/about/versions/nougat/android-7.0#default_trusted_ca)
* Update to _Keymaster 2_ with support for [Key Attestation](https://source.android.com/docs/security/features/keystore/attestation#key-attestation) and version binding (preventing rolling back to an unsecure old version without losing keys), see [Key Attestation section of Android 7.0 for Developers](https://developer.android.com/about/versions/nougat/android-7.0#key_attestation) and [Keymaster Functions](https://source.android.com/docs/security/features/keystore/implementer-ref) and [Verifying hardware-backed key pairs with Key Attestation
](https://developer.android.com/training/articles/security-key-attestation) and [Key and ID Attestation
](https://source.android.com/docs/security/features/keystore/attestation)
* [File Based Encryption (FBE)](https://source.android.com/docs/security/features/encryption/file-based) introduced, but it's optional to implement by manufacturers, see [Direct Boot section of Android 7.0 for Developers](https://developer.android.com/about/versions/nougat/android-7.0#direct_boot) and [Support Direct Boot mode](https://developer.android.com/training/articles/direct-boot) and [Encryption](https://source.android.com/docs/security/features/encryption)
* Updated [SELinux](https://source.android.com/docs/security/features/selinux) configuration: further locking down application sandbox, breaking up mediaserver stack into smaller processes with reduced permissions (mitigation against Stagefright), see [Security-Enhanced Linux in Android](https://source.android.com/docs/security/features/selinux)

## Android 8 (API 26) - Oreo

[Security Enhancements in Android 8.0](https://source.android.com/docs/security/enhancements/enhancements80)

* _JavaScript_ evaluation runs in a separate process in `WebView` so _JavaScript_ code cannot access the app's memory so easily, see [What’s new in WebView security](https://android-developers.googleblog.com/2017/06/whats-new-in-webview-security.html) and [Security section of Android 8.0 Behavior Changes for All Apps
](https://developer.android.com/about/versions/oreo/android-8.0-changes#security-all)
* `WebView` respects [Network Security Config](https://developer.android.com/training/articles/security-config) and `cleartextTrafficPermitted` flag (on older Android versions it loads _HTTP_ sites even if _clear text traffic_ should not be allowed by the config), see [Security section of Android 8.0 Behavior Changes for Apps Targeting Android 8.0](https://developer.android.com/about/versions/oreo/android-8.0-changes#o-sec)
* [Safe Browsing API](https://developer.android.com/develop/ui/views/layout/webapps/managing-webview#safe-browsing) added to `WebView` so users would be warned when trying to navigating to a potentially unsafe website (verified by [Google Safe Browsing](https://developers.google.com/safe-browsing/)) if enabled, see [WebView APIs section of Android 8.0 Features and APIs](https://developer.android.com/about/versions/oreo/android-8.0#wv)
* `FLAG_SECURE` `Window` flag is supported more and disallows taking screenshots of the screen where this is set
* Update to _Keymaster 3_ with rewritten [Hardware Abstraction Layers (HALs)](https://source.android.com/docs/core/architecture/hal) written in _HAL Interface Definition Language (HIDL)_ and in C++ (as compared to [Legacy HAL](https://source.android.com/docs/core/architecture/hal/archive) that was written in C) with [ID attestation](https://source.android.com/docs/security/features/keystore/attestation#id-attestation) support, see [Hardware-backed Keystore](https://source.android.com/docs/security/features/keystore) and [Keymaster Functions](https://source.android.com/docs/security/features/keystore/implementer-ref) and [Key and ID Attestation
](https://source.android.com/docs/security/features/keystore/attestation)
* _Project Treble_ introduced (only devices released with this version support project Treble, the ones updated will not get it), separating lower-level vendor code from Android system framework and enabling easier security update delivery, see [Here comes Treble: A modular base for Android](https://android-developers.googleblog.com/2017/05/here-comes-treble-modular-base-for.html) and [Treble Plus One Equals Four](https://android-developers.googleblog.com/2020/12/treble-plus-one-equals-four.html)
* Updated [SELinux](https://source.android.com/docs/security/features/selinux) to work with _Treble_. _SELinux_ policy allows manufacturers and SOC vendors to update their parts of the policy independently from the platform and vice versa, see [Security-Enhanced Linux in Android](https://source.android.com/docs/security/features/selinux)
* Further hardening media stack: mobild [Hardware Abstraction Layers (HALs)](https://source.android.com/docs/core/architecture/hal) from running in a shared process to running in their own sandboxed processes
* To allow installing apps from unknown sources (i.e. not from _Google Play_) apps need explicit permission granted by the user for the particular app in Android settings (and users can revoke such permission and manage it per-app at any time too), see [User opt-in for unknown apps and sources section of Publish your app](https://developer.android.com/studio/publish#publishing-unknown) and [Security section of Android 8.0 Behavior Changes for All Apps](https://developer.android.com/about/versions/oreo/android-8.0-changes#security-all)

## Android 9 (API 28) - Pie

[Security Enhancements in Android 9](https://source.android.com/docs/security/enhancements/enhancements9)

[Android 9 release notes - Security features](https://source.android.com/docs/setup/about/p-release-notes#security_features)

* _Cleartext network traffic (HTTP)_ disabled by default, apps need to explicitly set `cleartextTrafficPermitted` to `true` in their [Network Security Config](https://developer.android.com/training/articles/security-config) it if they still want to use it (not recommended), see [Network TLS enabled by default section of Behavior changes: apps targeting API level 28+
](https://developer.android.com/about/versions/pie/android-9.0-changes-28#tls-enabled) and [Android: Cleartext HTTP traffic not permitted Android 9](https://nphausg.medium.com/android-8-cleartext-http-traffic-not-permitted-73c1c9e3b803)
* Update to _Keymaster 4_ with support for _3DES_ encryption and secure key import, see [Hardware-backed Keystore](https://source.android.com/docs/security/features/keystore) and [Keymaster Functions](https://source.android.com/docs/security/features/keystore/implementer-ref)
* Replace many _BouncyCastle_ implementations of cryptographic algorithms with _Conscrypt_ ones, see [Conscrypt implementations of parameters and algorithms section of Android 9 Behavior changes: all apps](https://developer.android.com/about/versions/pie/android-9.0-changes-all#conscrypt_implementations_of_parameters_and_algorithms)
* Added support for embedded [Secure Element (SE)](https://source.android.com/docs/compatibility/cts/secure-element), see [Secure Element (SE) service section of Android 9 release notes
](https://source.android.com/docs/setup/about/p-release-notes#secure_element_se_service) and [CTS test for Secure Element](https://source.android.com/docs/compatibility/cts/secure-element)
* _Disk Encryption_ (can be either [Full Disk Encryption (FDE)](https://source.android.com/docs/security/features/encryption/full-disk) or [File Based Encryption (FBE)](https://source.android.com/docs/security/features/encryption/file-based)) is mandatory for all devices (shipping with this version)
* [BiometricPrompt](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt) introduced standardizing the UI that is shown during biometric authentication and providing a better API to apps that is harder to misuse, the previous solution, [FingerprintManager](https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager) gets _deprecated_, see [Show a biometric authentication dialog](https://developer.android.com/training/sign-in/biometric-auth)

## Android 10 (API 29) - Quince Tart

[Security Enhancements in Android 10](https://source.android.com/docs/security/enhancements/enhancements10)

[Android 10 release notes - Security features](https://source.android.com/docs/setup/about/android-10-release#security_features)

* File access disabled by default in `WebView`, see [setAllowFileAccess method of WebSettings](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean))
* [TLS 1.3](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_1.3) become available and enabled by default, see [TLS 1.3 enabled by default section of Android 10 Behavior changes: all apps](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3)
* Certificates signed with _SHA-1_ no longer trusted in _TLS_
* Background apps cannot launch other _Activities_ (e.g. other apps), see [Background apps launching section of Android 10 release notes](https://source.android.com/docs/setup/about/android-10-release#background_apps_launching) and [Background activity restrictions section of Security and Privacy Enhancements in Android 10](https://source.android.com/docs/security/enhancements/enhancements10#background-activity)
* [File Based Encryption (FBE)](https://source.android.com/docs/security/features/encryption/file-based) is mandatory for devices that launch with this Android version (devices updated to it can still continue using [Full Disk Encryption (FDE)](https://source.android.com/docs/security/features/encryption/full-disk)), see [Encryption](https://source.android.com/docs/security/features/encryption)
* `FLAG_SECURE` flag is added for biometric or device credential (_PIN_, _pattern_ or _password_) prompts, including both unlocking the device and [BiometricPrompt](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt) in apps - this means you cannot take a screenshot of these screens and they also appear blacked out in screen shares, see [source for com.android.systemui.biometrics.AuthContainerView on Android Code Search](https://cs.android.com/android/platform/superproject/+/master:frameworks/base/packages/SystemUI/src/com/android/systemui/biometrics/AuthContainerView.java;l=843;bpv=0;bpt=0)
* Only the default [Input Method Editor (IME)](https://developer.android.com/develop/ui/views/touch-and-input/creating-input-method) app can access _Clipboard_ data from the background, see [Limited access to clipboard data section of Privacy changes in Android 10](https://developer.android.com/about/versions/10/privacy/changes#clipboard-data) and [Clipboard data section of Security and Privacy Enhancements in Android 10](https://source.android.com/docs/security/enhancements/enhancements10#clipboard-data)
* [StrandHogg 2.0](https://promon.co/resources/downloads/strandhogg-2-0-new-serious-android-vulnerability/) exploit ([CVE-2020-0096](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0096)) no longer possible (a patch for the vulnerability is also backported to _Android 8.0_, _8.1_ and _9.0_ with the [May 2020 security update](https://source.android.com/docs/security/bulletin/2020-05-01) - if the manufacturer released the update to a device), see [StrandHogg Attack / Task Affinity Vulnerability](https://developer.android.com/topic/security/risks/strandhogg) and [StrandHogg 2.0 Exploit Explained - Why Users and Android App Developers should care](https://www.xda-developers.com/strandhogg-2-0-android-vulnerability-explained-developer-mitigation/) and [Strandhogg Vulnerability](https://androidexplained.github.io/security/android/malware/2020/09/23/strandhogg.html)

## Android 11 (API 30) - Red Velvet Cake

[Security Enhancements in Android 11](https://source.android.com/docs/security/enhancements/enhancements11)

[Android 11 release notes - Secure](https://source.android.com/docs/setup/about/android-11-release#secure)

* _Task Hijacking_ ([StrandHogg 1.0](https://promon.co/security-news/the-strandhogg-vulnerability/)) exploit (when another app sets its `taskAffinity` to the same as the target to trick the user to launch it even if they inteded to launch the target app and used it's legitimate app icon) no longer possible, see [StrandHogg Attack / Task Affinity Vulnerability](https://developer.android.com/topic/security/risks/strandhogg) and [Strandhogg Vulnerability](https://androidexplained.github.io/security/android/malware/2020/09/23/strandhogg.html)
* Apps can no longer query information about other installed apps by default, see [Package visibility filtering on Android
](https://developer.android.com/training/package-visibility) and [Package visibility in Android 11](https://medium.com/androiddevelopers/package-visibility-in-android-11-cc857f221cd9)
* _Runtime Permissions_ auto-reset for unused apps, see [Auto-reset permissions from unused apps section of Permissions updates in Android 11
](https://developer.android.com/about/versions/11/privacy/permissions#auto-reset) and [Auto-reset permissions of unused apps section of Request runtime permissions](https://developer.android.com/training/permissions/requesting#auto-reset-permissions-unused-apps)
* [Scoped Storage](https://source.android.com/docs/core/storage/scoped) introduced, but apps can still opt-out of it via `requestLegacyExternalStorage`, see [Storage updates in Android 11](https://developer.android.com/about/versions/11/privacy/storage) and [Opt out in your production app section of Android storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases#opt-out-in-production-app)

## Android 12 (API 31) - Snow Cone

[Android 12 release notes](https://source.android.com/docs/setup/about/android-12-release)

* `android:exported` flag needs to be defined _explicitly_ in Manifests for components (_Activities_, _Content Providers_, etc.) that declare [Intent Filters](https://developer.android.com/guide/topics/manifest/intent-filter-element), see [Safer component exporting section of Behavior changes: Apps targeting Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#exported)
* Generic web _Intents_ resolve to user's default browser app _unless_ the target app is approved for the specific domain contained in that web _Intent_, see [Web intent resolution section of Android 12 Behavior changes: all apps](https://developer.android.com/about/versions/12/behavior-changes-all#web-intent-resolution)
* Replace more _BouncyCastle_ implementations of cryptographic algorithms with _Conscrypt_ ones, see [BouncyCastle implementation removed section of Android 12 Behavior changes: all apps](https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle)
* The user gets notified if an app accesses _Clipboard_ data of another app for the first time, see [System notification shown when your app accesses clipboard data section of Copy and paste
](https://developer.android.com/develop/ui/views/touch-and-input/copy-paste#PastingSystemNotifications)
* Apps can no longer close _System Dialogs_, see [Apps can't close system dialogs section of Android 12 Behavior changes: all apps](https://developer.android.com/about/versions/12/behavior-changes-all#close-system-dialogs)
* [Tapjacking](https://developer.android.com/topic/security/risks/tapjacking) mitigation: Apps are prevented from consuming touch events where an overlay obscures the app, see [Cloak & Dagger](https://cloak-and-dagger.org/)
* [Scoped Storage](https://source.android.com/docs/core/storage/scoped) always enforced, opting out of it via `requestLegacyExternalStorage` is no longer possible, see [Opt out in your production app section of Android storage use cases and best practices](https://developer.android.com/training/data-storage/use-cases#opt-out-in-production-app)

## Android 13 (API 33) - Tiramisu

[Android 13 release notes - Security](https://source.android.com/docs/setup/about/android-13-release#security)

* Non-matching _Intents_ are blocked by _Intent filters_ (apps cannot send an _Intent_ to another app's exported component unless it fully matches the _Intent filter_ defined by it), see [Intents should match declared intent filters section of Android 13 and Android 13 QPR release notes
](https://source.android.com/docs/setup/about/android-13-release#declared-intent-filters)
* Only [File Based Encryption (FBE)](https://source.android.com/docs/security/features/encryption/file-based) is allowed, [Full Disk Encryption (FDE)](https://source.android.com/docs/security/features/encryption/full-disk) is no longer - not even for devices updated from a version that it was allowed
