..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Background
==========

The mechanisms that shirudo combines come from the kernel, the boot
chain, the TPM, cryptography, container registries and telemetry. Each
page here explains one of them for a reader who has not worked with it,
as far as shirudo depends on it. A reader who knows a mechanism can skip
its page.

.. toctree::
   :titlesonly:

   bpf
   co-re-btf
   bpf-signing
   bpf-lsm
   fentry-fexit
   fmod-ret
   keyrings
   xattrs
   dm-verity
   initrd-dracut
   boot
   tpm
   pqc
   oci
   opentelemetry
   siem-export
   luajit
