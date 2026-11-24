..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

fentry and fexit attachments
============================

To observe what the kernel does, a program has to run where it happens:
when a function is called, with which arguments, and what it returns.
``fentry`` and ``fexit`` attach a BPF program to the entry and to the
return of a kernel function. The kernel generates a small piece of
machine code for each function that has such programs, a BPF
trampoline, and the function's entry calls it directly.

The same trampoline carries ``fmod_ret`` programs, which can fail a
call, and the ``lsm`` programs shirudo's own enforcement consists of.
This page explains what the two observing kinds see, how the trampoline
works, which functions it reaches, and how it differs from a kprobe.

Programs at the entry and the return
------------------------------------

Both kinds are tracing programs, ``BPF_PROG_TYPE_TRACING``, with the
attach types ``BPF_TRACE_FENTRY`` and ``BPF_TRACE_FEXIT``. In source,
the section names the function, as in ``SEC("fentry/ksys_unshare")``,
and ``BPF_PROG()`` lists the function's parameters. An ``fexit``
program lists one more, the value the function returned:

.. code-block:: c

   __u64 failures;

   SEC("fexit/vfs_fallocate")
   int BPF_PROG(count_failures, struct file *file, int mode,
                loff_t offset, loff_t len, int ret)
   {
           if (ret < 0)
                   __sync_fetch_and_add(&failures, 1);
           return 0;
   }

Three properties set these programs apart from older ways to trace a
function.

The arguments have types. The verifier takes the prototype of the
function from the kernel's BTF (see :doc:`co-re-btf`) and knows what
each parameter is. A program follows a pointer to a kernel structure
field by field in plain C, and the verifier checks every access against
the layout of that structure.

An ``fexit`` program sees the arguments and the result together. The
trampoline saves the arguments when the call comes in and shows the
program that copy, so the program reads what the caller passed even
after the function changed its own variables.

The programs only observe. The verifier requires both kinds to return
0. They cannot write through the pointers they get, and a read through
such a pointer tolerates a fault and then yields 0. The pointers are
not trusted: kfuncs that require a trusted pointer refuse them.

BPF trampoline
--------------

The compiler leaves room for a call at the entry of every kernel
function that ftrace may trace, and in a running kernel that place
holds a nop. With ``CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS``, ftrace
can patch it into a direct call of any address. A trampoline is what
the entry calls once a program is attached. Figure 1 shows the three
states of a function's entry.

.. figure:: /images/background-trampoline.svg
   :alt: Three rows for a call f(a, b). With no program attached, the
         entry of f() is a nop and the call runs on into the body. With
         fentry programs only, the entry calls the trampoline, which
         saves a and b, runs the fentry programs, restores a and b and
         continues in the body, which returns to the caller. With an
         fexit or fmod_ret program, the entry enters the trampoline,
         which saves a and b, runs the fentry and fmod_ret programs,
         calls the body, runs the fexit programs with a, b and the
         result r, and returns r to the caller itself.

   Figure 1. The entry of a function without programs, with ``fentry``
   programs, and with a program that needs the result.

The kernel writes the trampoline when the first program attaches. From
BTF it derives a model of the function: how many parameters it has, how
large each is, and the size of its result. The JIT compiler emits code
for that model. The code stores the argument registers in an array on
the stack, which is the context every program of the function
receives, and then calls the programs one by one.

What follows depends on the programs:

- With ``fentry`` programs only, the trampoline restores the argument
  registers and returns into the body of the function. The function
  runs as if nothing had happened and returns to its caller.
- With an ``fexit`` or ``fmod_ret`` program, the trampoline calls the
  body itself, so that control comes back to it. It stores the result
  behind the arguments, runs the ``fexit`` programs, and returns the
  result to the caller of the function.

Around each program the trampoline calls two small kernel functions.
The first disables migration to another CPU, enters an RCU read-side
section and checks that the same program is not already running on this
CPU. The second undoes that and, when ``kernel.bpf_stats_enabled`` is
set, adds the run to the program's run count and run time. A sleepable
program gets the variant of RCU that allows sleeping.

A function has one trampoline for all its programs, of all four kinds.
Each attach and detach generates a new image with the programs that
are attached then, and ftrace switches the entry from the old image to
the new one. The kernel frees an old image only when no task can still
be in it. An image is at most 4 KB, and the kernel refuses an attach
whose image would be larger with ``E2BIG``. How many programs fit
depends on the kind and the architecture: 57 ``fentry`` or ``fexit``
programs on x86-64, and about 35 ``fmod_ret`` programs on x86-64 and
arm64 [#limit]_.

The entry instruction stays under ftrace's control. A function tracer,
a kprobe at the entry or a live patch can use the same function while
a trampoline is attached to it, and the trampoline of a live-patched
function calls the replacement.

Functions a trampoline reaches
------------------------------

A program can attach where three conditions hold:

- The function has an entry in BTF. A function the compiler inlined
  into all its callers has none, and neither has one whose parameters
  the compiler changed, as it does for some static functions.
- A trampoline can pass the parameters: at most 12, a structure passed
  by value of at most 16 bytes, and no variable arguments.
- The entry has the instruction ftrace patches. Functions marked
  ``notrace`` have none.

The kernel refuses a handful of functions that the trampoline itself
runs on, such as ``migrate_disable()`` and ``__rcu_read_lock()``, and it
refuses ``fexit`` on functions that never return, such as ``do_exit()``.

A program attaches to the entry of a function, not to its name. Where
the compiler inlined the function into one of its callers, that caller
does not pass the entry, and the program does not run for it.

The sleepable forms, ``fentry.s`` and ``fexit.s``, are admitted only
where the kernel knows that sleeping is allowed: on system call entry
points and, on a kernel built with ``CONFIG_FUNCTION_ERROR_INJECTION``,
on the functions marked for error injection that may sleep. Any other
function can be called with a spinlock held or from an interrupt, and
nothing in its prototype says so.

Comparison with kprobes
-----------------------

A kprobe is the older and more general tool. It can stop at nearly any
instruction of the kernel, whether or not BTF describes the function
around it. Figure 2 shows what lies between the kernel function and
the program in each case.

.. figure:: /images/background-probe-paths.svg
   :alt: Three rows. For fentry, fexit, fmod_ret and lsm, the entry of
         f() makes a direct call to the BPF trampoline made for f(),
         which runs the program with arguments typed by BTF. For kprobe
         and kretprobe, a place in f(), its entry or an instruction, is
         a breakpoint, or ftrace at the entry, which leads to the kprobe
         and its handler, then to the perf event and its programs, and
         to the program with struct pt_regs. For kprobe.multi and
         kretprobe.multi, the entry of each function goes through
         ftrace's function graph tracer and one fprobe for the link to
         the program with struct pt_regs.

   Figure 2. From a kernel function to the program, for a trampoline, a
   kprobe and a ``kprobe.multi`` link.

.. list-table::
   :header-rows: 1
   :widths: 22 39 39

   * -
     - ``fentry``, ``fexit``
     - ``kprobe``, ``kretprobe`` and their ``.multi`` forms
   * - Place
     - Entry and return of a function that BTF describes.
     - Entry and return of any function in kallsyms. A ``kprobe`` also
       takes an instruction inside a function.
   * - Way to the program
     - A direct call from the function's entry to code generated for
       this function.
     - For a ``kprobe``, a breakpoint and its exception, or ftrace at
       the entry of a function on x86-64, then the kprobe's handler and
       the perf event. For the ``.multi`` forms, ftrace's function
       graph tracer and one fprobe for all functions of the link.
   * - Context
     - The arguments, each with its BTF type. ``fexit`` gets the return
       value as well.
     - ``struct pt_regs``, the registers at the probe. The program
       picks arguments out of them with macros for the architecture.
   * - Check at load
     - The verifier binds the program to one function of the kernel's
       BTF and checks the prototype. A function the kernel lacks fails
       the load.
     - None against the function. The symbol is resolved when the
       program is attached.
   * - At the return
     - Arguments as passed, and the result.
     - The registers at the return, which hold the result and no longer
       the arguments.
   * - Changing the outcome
     - None. ``fmod_ret`` on the same trampoline can fail a call (see
       :doc:`fmod-ret`).
     - ``bpf_override_return()`` at the entry of a function on the
       error-injection list, on a kernel built with
       ``CONFIG_BPF_KPROBE_OVERRIDE``.
   * - Runs the kernel skips
     - A run of a program that is already running on the CPU.
     - A run while any program of these kinds runs on the CPU, and
       returns the probe has no room to track.
   * - Kernel options
     - Those shirudo itself needs.
     - ``CONFIG_KPROBES`` and ``CONFIG_KPROBE_EVENTS``, or
       ``CONFIG_FPROBE`` for the ``.multi`` forms.

The table gives the rule of thumb. Where BTF describes the function,
``fentry`` and ``fexit`` are the better choice: the program is checked
against the kernel it loads on, reads typed arguments, and costs a
direct call. A kprobe remains for a function without a BTF entry and
for a place inside a function. Neither is a stable interface. Kernel
functions are renamed, inlined and given new parameters from one
release to the next. Where a tracepoint or an LSM hook covers the
event, ``tp_btf`` and ``lsm`` programs attach to a place the kernel
keeps on purpose.

How shirudo uses trampolines
----------------------------

shirudo's enforcement runs on trampolines. Every program of its
``bpf2`` and ``seal`` objects is an ``lsm`` program, and an ``lsm``
program attaches through the trampoline of the empty function the BPF
LSM provides for its hook (see :doc:`bpf-lsm`). That is why BPF
trampolines and ftrace direct calls are among the kernel options
shirudo cannot do without (:doc:`/operate/plan/system-requirements`).

A upatch uses them for its own programs. ``shirudo build`` accepts
``fentry/<function>`` and ``fexit/<function>`` sections and their ``.s``
forms. The signed loader looks the function up in the target's BTF and
loads the program bound to it, and ``shirudo upatch load`` attaches it
and pins the link (:doc:`/upatches/write/attach-kinds`). The function
is therefore part of what the operator signed: the program runs at the
function its source names, or the load fails.
:src:`upatches/kernel-obs/userns-unshare-counter.bpf.c` is a small
example, an ``fentry`` program that counts the ``unshare(2)`` calls
that ask for a user namespace.

A upatch's programs share a function's trampoline with every other
program on that function. On an LSM hook these include shirudo's own.
:doc:`/operate/plan/scalability` gives the limits.

Limits
------

- A trampoline reaches the entry and the return of functions that BTF
  describes and ftrace can patch. It reaches no place inside a
  function and no inlined copy of one.
- Kernel functions are not an interface. A upatch that attaches to one
  is tied to the kernels that have it under that name and with those
  parameters. On another kernel its load fails, which
  :doc:`/upatches/test/debugging` shows how to recognize.
- ``fentry`` and ``fexit`` observe. Refusing an operation takes an
  ``lsm`` program, or ``fmod_ret`` where no hook covers it.
- The kernel skips a run of a program that is already running on the
  CPU, so a count such a program keeps is a lower bound.
  :ref:`runs-the-kernel-skips` gives the cases.
- Pointer arguments are not trusted. A read through one can yield 0 or
  data of an object that was freed meanwhile.
- A function takes as many programs as fit its 4 KB image, shirudo's
  own included.

Related
-------

- :doc:`fmod-ret` for the programs that fail a call
- :doc:`bpf-lsm` for the hooks and their programs
- :doc:`co-re-btf` for the type information the verifier checks against
- :doc:`/upatches/write/attach-kinds` for every kind ``shirudo build``
  accepts
- :doc:`/upatches/write/pitfalls` for what each kind misses
- :doc:`/upatches/write/memory-consistency/hazards` for runs that
  interleave

.. [#limit] The counts are those of the kernel change that made the
   image size the only limit, `bpf: Remove BPF_MAX_TRAMP_LINKS
   <https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/commit/?id=cfe2171b0bd9839c3a7d770c37bfab122c1b4271>`__.
   They vary with the programs' options and the kernel's configuration.
