# AndroidSecurityEvolution
Significant security enchancements of recent major Android versions, starting with Android 5.0 Lollipop (API 21).

## Android 5.0 - Lollipop (API 21)

* Starting 2023, Google Play Services updates will only be received from this Android version
* Full Disk Encryption (FDE) by default (manufacturers can still opt out)
* SELinux fully enforced

## Android 6 - Marshmallow (API 23)

* Keystore and Keymaster introduced
* TEE is a requirement
* New APIs for checking whether a KeyStore key is stored in secure hardware
* Apps need to request permissions at runtime
* More restrictive SELinux (IOCTL filtering, tightening of SELinux domains, etc.)

## Android 7 - Nougat (API 24)

* Separate User and System Certificate Trust Store, meaning Man-in-the-Middle attacks require root access
* Update to Keymaster 2 with support for key attestation and version binding (preventing rolling back to an unsecure old version without losing keys)
* File Based Encryption (FBE) introduced, but it's optional to implement by manufacturers
* Updated SELinux configuration: further locking fown application sandbox, breaking up mediaserver stack into smaller processes with reduced permissios (mitigation against Stagefright)

## Android 8 - Oreo (API 26)

* JavaScript evaluation runs in a separate process in WebViews so JavaScript code cannot access the app's memory so easily
* FLAG_SECURE Window flag is supported more and disallows taking screenshots of the screen where this is set.
* Update to Keymaster 3 with C++ HAL (instead of a C one), addition of HIDL and ID attestation support
* Project Treble introduced separating lower-level vendor code from Android system framework and enabling easier security update delivery. Keep in mind that only devices released with this version support project Treble, the ones updated will not get it.
* Updated SELinux to work with Treble. SELinux policy allows manufacturers and SOC vendors to update their parts of the policy independently from the platform and vice versa.
* Further hardening media stack: mobild Hardware Abstraction Layers (HALs) from running in a shared process to running in their own sandboxed processes.

## Android 9 - Pie (API 28)

* Cleartext network traffic (HTTP) disabled by default, apps need to opt-in if they want to use it
* Update to Keymaster 4 with support for 3DES encryption and secure key import
* Added support for embedded SE (Secure Element)
* Reading contents of the Clipboard in the background requires special permission
* Disk Encryption (can be either Full Disk Encryption or File Based Encryption) is mandatory for all devices (shipping with this version)
* BiometricPrompt introduced standardizing the UI that is shown during biometric authentication and providing a better API to apps that is harder to misuse

## Android 10 - Quince Tart (API 29)

* File access disabled by default in WebViews
* TLS 1.3 enabled by default
* Certificates signed with SHA-1 no longer trusted in TLS
* System overlay permissions are reset on reboot for apps downloaded from Google Play, and after 30 seconds for sideloaded apps.
* Background apps cannot launch other Activites (e.g. other apps)
* File Based Encryption (FBE) is mandatory for devices that launch with this Android version (devices updated to it can still continue using Full Disk Encryption)
* FLAG_SECURE flag is added for biometric or device credential (PIN, pattern or password) prompts, including unlocking the device and BiometricPrompt in apps. This means you cannot make a screenshot of these screens and they appear black in screen shares.

## Android 11 - Red Velvet Cake (API 30)

* Task Hijacking (StrandHogg 1.0) vulnerability no longer possible
* Apps cannot query information about other installed apps by default
* Permissions auto-reset for unused apps

## Android 12 - Snow Cone (API 31)

* Exported flag needs to be defined explicitly in Manifests for components with Intent Filters
* Generic web intents resolve to user's default browser app unless the target app is approved for the specific domain contained in that web Intent
* Replace many BouncyCastle implementations of cryptographic algorithms with Conscrypt ones
* The user gets notified if an app accesses Clipboard data of another app for the first time
* Apps can no longer close System Dialogs
* Tapjacking mitigation: Apps are prevented from consuming touch events where an overlay obscures the app
* Scoped storage always enforced, opting out of it via requestLegacyExternalStorage is no longer possible

## Android 13 - Tiramisu (API 33)

* Non-matching Intents are blocked by Intent filters (apps cannot send an Intent to another app's exported component unless it fully matches the Intent filter defined by it)
* Only File Based Encryption (FBE) is allowed, Full Disk Encryption is no longer - not even for devices updated from a version that it was allowed
