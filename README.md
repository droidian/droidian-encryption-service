droidian-encryption-service
===========================

This service handles dm-crypt/LUKS encryption for a Droidian installation.

This document is not only specific to the actual encryption service, but also
as a bit of background on how disk encryption in Droidian works.

Overview
--------

In standard desktop GNU/Linux distributions, encryption is usually set-up during
the installation phase. 

This is definitely the most solid way, the LUKS container is created before the
target filesystem and the actual distro installation, so the files are only
written once.

On mobile devices, booting an installer from a different media is difficult or
a no-go altogether.

Some distros, such as postmarketOS or Mobian, provide an ["On-device installer"](https://wiki.postmarketos.org/index.php?title=On-device_installer)
that will set-up the target LUKS container (if enabled) and extract the actual
distro content ("Target OS") to the device storage.

It works nicely and is pretty close to the behaviour of desktop GNU/Linux distros
when it comes to LUKS. The only remarkable difference is that the Target OS
is written on disk two times (the first one being as part of the installer, and
the second during the final extraction), but that is a given.

Another thing is that someone not interested in having (full disk) encryption
would have to wait for the operating system to be installed a second time (after
waiting during the initial installer flash). It's definitely not an huge issue,
but can it be improved somehow?

Encryption in Droidian
----------------------

Since Droidian is perpetually in an experimental-alpha state, it's possible to
experiment a bit with this kind of stuff, since there isn't an expectation of
things to work.

The core of the encryption support in Droidian is the `reencrypt` feature of
(lib)cryptsetup.

Among other things, it allows to encrypt an existing unencrypted block device,
which is useful to us. The best thing is that (on LUKS2) it also allows online
re-encryption, which means that the actual process is transparent to the user.

A typical fastboot-flashable Droidian image (to not be confused with the rootfs
zipfiles that are meant to be flashed via a suitable Android recovery) flash
the device's `userdata` this way:


```
userdata (LVM PV)
\__ droidian (LVM VG)
    \__ droidian-persistent (LVM LV, 16M, empty)
    \__ droidian-reserved   (LVM LV, 32M. empty)
    \__ droidian-rootfs     (LVM LV, rest, contains the actual Droidian rootfs)
```

One of the possibly destructive things (beyond the actual re-encryption process!)
when using `cryptsetup reencrypt` is the fact that the partition needs to be
shrunk to house the LUKS2 metadata.

On Droidian, this is avoided by reserving a chunk of space in a separate volume,
which is the second one in the VG (`droidian-reserved`).  
This space can be used to house a detached LUKS2 header, thus avoiding the need
to resize the actual rootfs partition.

### Encryption set-up

After flashing Droidian, if the user doesn't need encryption, everything it's
good to go.

Otherwise, it can interact with `droidian-encryption-service` to set-up the
encryption (mostly creating the LUKS2 header, including choosing the slot
password).

`droidian-encryption-service` exposes a DBus system service that allows to
configure encryption for the first time and to get the current encryption status.

### Security considerations

During initial configuration, the password is sent as cleartext via DBus to the
service. The default configuration in Debian/Droidian forbids eavesdropping on
system services (such as `droidian-encryption-service`).

### Unlock and re-encryption

Once the encryption has been set-up, the user is supposed to reboot their device
to start the actual encryption process. In fact, during the set-up the only thing
that has been done is creating the header in the proper place (`droidian-reserved`).

The initramfs will detect whether to ask for a password (i.e. whether encryption
is present or at least set-up) and will prompt the user for it.

The given password is then passed on to `droidian-encryption-helper`, that is
embedded in the initramfs as well and does the following things:

1) Opens the LUKS container
2) If encryption has not ended, it forks itself and resumes the encryption process
3) Returns so that the boot process is not blocked - the encryption continues in the
background

Sending `SIGTERM` to the helper process will make it exit and pause the encryption
process. It is expected that this signal is sent to the helper (if running) when
shutting down or rebooting so that the encryption can be paused cleanly.
