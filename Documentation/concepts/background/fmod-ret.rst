..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

fmod_ret attachments
====================

A bug in the kernel stays reachable until a kernel with the fix boots,
and for a production machine that reboot can be days or weeks away.
Until then it matters whether user space can still reach the code with
the bug. A BPF program attached as ``fmod_ret`` can close the way to it
at one kernel function. It runs before the function, looks at the
arguments and either lets the call proceed or fails it with an error.

By default, the functions that take such a program are a short list
that kernel developers keep by hand. A kernel built with
``CONFIG_BPF_FMODRET_SCAN`` adds the functions its build finds in its
own machine code, and holds every program to the errors its target
returns anyway [#series]_. This page explains how an ``fmod_ret``
program runs, how the build finds its targets, what the verifier checks
at load, and where the mechanism stops.

Failing a call
--------------

``fmod_ret`` attaches a tracing program, ``BPF_PROG_TYPE_TRACING``, with
the attach type ``BPF_MODIFY_RETURN``. In source, the section names the
function, as in ``SEC("fmod_ret/vfs_fallocate")``. The program receives
the arguments of the function with their types and returns an integer:

- ``0`` lets the function run. The caller gets what the function returns.
- Any other value skips the body of the function. The caller gets that
  value as if the function had returned it.

This program refuses one mode of ``fallocate(2)`` and leaves every other
call alone:

.. code-block:: c

   #define FALLOC_FL_COLLAPSE_RANGE 0x08
   #define EOPNOTSUPP 95

   SEC("fmod_ret/vfs_fallocate")
   int BPF_PROG(no_collapse_range, struct file *file, int mode,
                loff_t offset, loff_t len, int ret)
   {
           if (mode & FALLOC_FL_COLLAPSE_RANGE)
                   return -EOPNOTSUPP;
           return 0;
   }

``BPF_PROG()`` lists the parameters of the function and one more,
``ret``, the slot that holds the value so far. It is 0 whenever an
``fmod_ret`` program runs, because the first program that returns
another value ends the sequence.

The program runs in a BPF trampoline, a piece of machine code that the
kernel generates for the function when the first program attaches (see
:doc:`fentry-fexit`). Figure 1 shows one call through it. The
trampoline runs ``fentry`` programs first, then ``fmod_ret`` programs.
When all of them return 0, it calls the body of the function. ``fexit``
programs run last either way and see the value the caller is about to
get.

.. figure:: /images/background-fmod-ret-call.svg
   :alt: A caller runs err = f(a, b). The call enters the BPF
         trampoline of f(), which runs fentry programs and then the
         fmod_ret program with a and b. When the program returns 0, the
         trampoline calls the body of f(), and r becomes its result.
         When the program returns an error, the body is skipped. In both
         cases fexit programs then see a, b and r, and the caller
         continues with err equal to r.

   Figure 1. One call of a function with an ``fmod_ret`` program.

On x86-64 and arm64 the trampoline fits the value to the return type of
the function before it tests it: the low four bytes with their sign for
an ``int``, 0 or 1 for a ``bool``. The test, ``fexit`` programs and the
caller then see the same value.

An ``lsm`` program runs through the same code. The BPF LSM gives each
hook an empty function, and a program on a hook that returns an integer
attaches to it as an ``fmod_ret`` program does (see :doc:`bpf-lsm`).

Skipped calls and failed calls
------------------------------

A program that returns an error skips the function. That is not the
same as the function failing. A function that fails has often done part
of its work first, and its caller relies on that part.

Figure 2 shows the common case. The caller takes a lock and calls
``f()``, which releases the lock on every path, the failing ones
included. When ``f()`` fails, the lock is free. When a program returns
the same error in its place, nobody releases the lock, and the next
task that needs it hangs. The kernel's ``do_dup2()``, which ``dup2(2)``
reaches with the file table locked, is such a function.

.. figure:: /images/background-fmod-ret-skip.svg
   :alt: Two rows. In the first, a caller locks obj->lock and calls
         f(obj); f() unlocks obj->lock and returns -EBUSY; the caller
         sees -EBUSY and the lock is free. In the second, the caller
         does the same, but an fmod_ret program returns -EBUSY and f()
         does not run; the caller sees -EBUSY and the lock is still
         held.

   Figure 2. The same error from a function that fails and from a
   program that skips it.

Other functions free or initialize an object of the caller before they
return an error, and a skip leaves that undone as well. Callers add
assumptions of their own. One ignores the result because the function
cannot fail on its path. Another takes a particular error for a request
to retry.

The kernel therefore admits ``fmod_ret`` only on functions known to
tolerate it. Without the scan, these are the targets somebody declared:

- functions whose name starts with ``security_``, which call the LSM
  hooks
- entry points of system calls, such as ``__x64_sys_close``
- functions marked with ``ALLOW_ERROR_INJECTION()``, on a kernel built
  with ``CONFIG_FUNCTION_ERROR_INJECTION``
- functions a subsystem registers for return modification

On one x86-64 kernel that comes to about 1,300 functions: 957 system
call entry points, 312 ``security_*()`` functions and 21 others
[#series]_. A bug is rarely in one of them or directly behind one. Of
417 kernel fixes from one year that add a failing check to a function,
the fixed function was a declared target in 1 % of the cases. The
verifier does not restrict what a program returns on a declared target.

Targets the kernel build finds
------------------------------

Declaring targets by hand does not reach the thousands of functions in
networking, file systems and memory management where bugs are fixed.
``CONFIG_BPF_FMODRET_SCAN`` puts a rule in the place of a developer's
judgment, one the build can apply to every function. A function that
returns errors is a target. A program on it returns 0, or an error that
the function returns itself.

The reasoning is that every caller of the function can already receive
each of these errors, without any program. A program that returns one
of them shows the callers nothing they have not been written for. It
only decides on which call the failure happens.

Figure 3 shows the way from the linked kernel to a loaded program, with
the function of the example above.

.. figure:: /images/background-fmod-ret-scan.svg
   :alt: In the kernel build, vmlinux and the modules, machine code
         after inlining and the link, go through resolve_btfids
         --fmodret_scan, which decodes instructions with LLVM's MC
         layer, analyzes which constants reach a return, filters the
         errors that count and writes one list per function as a tag
         into BTF: DECL_TAG
         'bpf_fmodret_retval:-95,-29,-27,-26,-22,-21,-19,-9,-1' on FUNC
         'vfs_fallocate'. In the running kernel, a program with
         SEC("fmod_ret/vfs_fallocate") that returns 0 or -EFBIG, which
         is -27, goes to the verifier, which checks at the load that the
         target has a tag and that R0 at each exit is 0 or in its list.
         The trampoline then calls the function for 0 and skips it for
         -27.

   Figure 3. From machine code to a tag in BTF, and from the tag to the
   check at load.

Machine code as the source
~~~~~~~~~~~~~~~~~~~~~~~~~~

The build applies the rule in ``resolve_btfids``, the tool that already
runs on ``vmlinux`` and on every module after the link, once their type
information is written (see :doc:`co-re-btf`). With ``--fmodret_scan``
the tool reads the machine code of each function, not its source. It
therefore sees what will run: the code after inlining and after the
link, from GCC or from clang, of the kernel and of its modules.

To follow a value through a function, the tool has to know of each
instruction its length, where it branches and which registers it
writes, the implicit ones included. It takes these facts from the
machine code layer of LLVM, which is why the build host needs LLVM's
headers and libraries even when GCC compiles the kernel. A small table
per architecture adds what an instruction computes: a move of a
constant, a copy, a sign extension, a select.

Errors that reach a return
~~~~~~~~~~~~~~~~~~~~~~~~~~

An error leaves a function as a small negative constant in the return
value register. The compiler may load the constant into any register
first and move it later, so the tool runs a data-flow analysis over the
function, backward from each return instruction. At every point it
keeps the set of registers whose value may still become the return
value:

- At a return, the set holds the return value register.
- Before a copy into a register of the set, the source takes the place
  of the destination.
- Any other write takes a register out of the set, and a call takes out
  every register the callee may overwrite.
- Where two paths meet, the sets are joined.

An instruction that loads a constant from -4095 to -1 into a register
that is in the set behind it loads an error the function can return.
One run answers the question for all constants of a function.

A 32-bit move of -22 leaves 4294967274 in a 64-bit register. That is
an error for a function that returns ``int`` and a large number for one
that returns ``long``, unless a sign extension follows. The analysis
therefore tracks how each copy converts the value, and a constant that
reaches a 64-bit return without its sign is no error. Compilers also
select between 0 and an error without a branch, from an instruction
that produces 0 or -1 and a mask. The tool folds such sequences into the
two constants they yield.

The analysis is deliberately coarse:

- It does not evaluate branches. A constant counts when any path of the
  control flow carries it to a return, so the list can hold an error
  that no run of the function returns.
- It does not follow values through memory. A constant the compiler
  spilled to the stack is lost.
- Where it cannot describe an instruction, it assumes that the
  instruction overwrites every register, which loses the constants
  before it.

Functions and errors left out
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The scan looks at a function only when a program could attach to it and
its result can carry an error:

- It returns an integer or an enum of 4 or 8 bytes. A function that
  returns a pointer, a ``bool`` or nothing gets no tag.
- No other function of ``vmlinux``, or of the module, has its name,
  because the type information knows a function by name alone.
- A trampoline can pass its parameters: at most 12, each of at most 16
  bytes, and no variable arguments.
- It is not initialization code, which the kernel frees after boot.
- Its entry has the instruction that ftrace patches. A ``notrace``
  function has none, and a function the compiler inlined into all its
  callers has no entry at all.

From the constants it found, the tool drops those that do not mean
failure:

- Codes of -512 and below, which the kernel uses internally and never
  hands to user space.
- ``-EAGAIN``, ``-EMSGSIZE`` and ``-EINPROGRESS``, which tell a caller
  to retry, to go on or to wait.
- ``-EBUSY`` in a function that also returns ``-EINPROGRESS``, where it
  says that a request was queued.
- -1 when it is the only error. The machine code cannot tell
  ``-EPERM`` from the -1 of a comparison or of "not found".

A function with no error left is not a target.

Errors that follow work on an argument
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The lock of Figure 2 is the case the rule must not admit, and the
machine code shows it. Before the failing function loads its error, it
calls the unlock function with a pointer it computed from its own
argument: the address of a member of the object the caller passed in.

The tool generalizes that observation. It leaves an error out of the
list when, on every path from the entry of the function to the return
of that error, the function hands a pointer based on one of its pointer
arguments to a callee that returns nothing. "Based on" means computed
without a load from memory, as ``&arg->lock`` is, so that the pointer
still points into the caller's object.

The condition needs no function names and no annotations. A callee that
returns nothing cannot have failed, so whatever it did to the object is
done when the error returns. Most unlock, put, free and init functions
are of that kind, and the type information says which callees return
nothing. A callee that returns a value may be the one that failed, and
does not count. A second analysis, forward from the entry, tracks which
registers hold a based pointer and whether a path without such a call
is left.

A function stays a target as long as its list keeps one error. In one
x86-64 build the condition removed about 2,000 of 22,100 errors and 900
of 13,000 functions, ``do_dup2()`` among them [#series]_.

Tag in the type information
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The result goes into BTF as a declaration tag on the function, whose
text is ``bpf_fmodret_retval:`` and the list. In the build of Figure 3,
``vfs_fallocate()`` carries nine errors, from ``-EOPNOTSUPP`` (-95) to
``-EPERM`` (-1). A module's functions are tagged in the module's own
BTF. The tag is the whole interface: the kernel keeps no second list of
targets, and anything that reads BTF can tell what a kernel admits.

One x86-64 configuration built with clang gets 12,096 tagged functions,
the same configuration built with GCC 11,432, and an arm64 build 10,954
[#series]_. A list is short. The functions of the clang build carry
about 20,000 errors between them, fewer than two each, and a program
picks from those. The tags add about 3 % to the size of BTF.
:doc:`/upatches/write/attach-kinds` shows how to print the tag of a
function.

The option is off by default and exists for x86-64 and arm64. It needs
BTF and ftrace direct calls, ``CONFIG_DEBUG_INFO_BTF`` and
``CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS``, and on the build host a
C++17 compiler and the headers and libraries of LLVM 17 or later with
the target of the kernel. The tool checks its table against the
installed LLVM each time it starts and stops the build when the two
disagree. It also stops the build when it cannot decode more than 1 %
of the functions it scans in ``vmlinux``, or tags none.

Check at load
-------------

When a program names a function as its ``fmod_ret`` target, the
verifier first looks for a declaration. If there is none, it looks for
the tag in the BTF object the function belongs to, the kernel's or the
module's own. A function with neither is refused with ``<function>() is
not modifiable``.

For a tagged target, the verifier keeps the list and tests R0, the
register that holds the return value, at every exit of the program:

- R0 holds a number, and every value it can hold there is 0 or in the
  list. Two constants on two paths pass. A range from -27 to -22 fails
  even when both ends are in the list, because the values between them
  are not.
- A function that returns ``int`` hands its caller the low 32 bits, so
  an error may be written as a 32-bit value. For a function that
  returns ``long`` all 64 bits count. A program declared to return
  ``int`` writes the 32-bit form, which is a large positive number
  there, and is refused. Declare such a program as ``long
  BPF_PROG(...)``.
- The exit of an exception callback and the value handed to
  ``bpf_throw()`` are held to the same list.
- A tail call is refused, because the program it jumps to would return
  in place of the checked one.

A program that fails the test is refused with ``At program exit the
register R0 should be 0 or one of``, followed by the list. A tagged
target takes no sleepable program: the ``fmod_ret.s`` form remains for
system call entry points and functions marked for error injection.

The verifier runs the check once, against the BTF of the kernel that
loads the program. Nothing of the list is compiled into the program.

Mitigation and hardening
------------------------

With the scan, most functions that validate input or dispatch a request
are targets, in the subsystems where bugs are found. For the 417 fixes
counted above, the fixed function is a target in 50 % of the cases
[#series]_. That widens what a BPF program can do about a bug that has
no LSM hook nearby.

A mitigation starts from the fix. The commit that fixes a bug says
which input is dangerous, usually as a new check that returns an error.
A program applies the same condition early, at the fixed function when
it is a target, or at a function on the way to it:

- It tests the arguments for the dangerous input and returns one of the
  function's errors for it.
- It returns 0 for everything else, so that every other use of the
  function keeps working.

Compared with blocking a whole module or a whole socket family, the
loss is the one kind of call that would have reached the bug.

Hardening uses the same mechanism with no particular bug in mind. A
machine that never uses a kernel feature can refuse the calls that set
it up: the registration of a protocol, a mode of a system call, a
request type of a driver. There the loss of function is the purpose.
The code stays in the kernel image, and user space no longer reaches
it.

In both cases a program only fails calls. It cannot change an argument,
make a call succeed that the function would refuse, or return a value
the function does not return. On a stock kernel a task needs
``CAP_BPF`` and ``CAP_PERFMON`` to load one, and attaching it does not
taint the kernel.

How shirudo uses fmod_ret
-------------------------

A upatch can carry ``fmod_ret`` programs. ``shirudo build`` accepts the
sections ``fmod_ret/<function>`` and ``fmod_ret.s/<function>`` and
records the kind and the function in the signed attach metadata. On the
target, the signed loader looks the function up in the kernel's BTF and
loads the program, which is when the verifier applies the rules above.
``shirudo upatch load`` then attaches it with ``BPF_LINK_CREATE`` and
``BPF_MODIFY_RETURN``, compares the link with the metadata and pins it.
See :doc:`/upatches/write/attach-kinds`.

Who can fail kernel calls is a question of who can load BPF. On a
shirudo target, the ``lsm/bpf`` and ``lsm/bpf_prog_load`` programs admit
only signed loaders (see :doc:`bpf-signing` and :doc:`bpf-lsm`). An
``fmod_ret`` program therefore reaches the kernel only inside a upatch
the operator signed, and root on the target cannot attach one of its
own. The load extends the measurement register as every upatch load
does, so evidence shows which mitigations a target runs.

Whether a function is a target depends on the target's kernel. A kernel
built without the scan offers the declared targets only. A upatch for
any other function fails to load there with ``verifier_rejected`` in
phase ``payload_load``. :doc:`/operate/plan/system-requirements` lists
the option, and :doc:`/upatches/test/debugging` the messages. The test
VM's kernel is built with the scan. Its configuration is small, and
about 5,700 of its 40,000 functions carry a tag.

Limits
------

The rule that makes a function a target is simple on purpose. It does
not prove that the kernel survives a skipped call.

- The kernel developers measured it. One program on one function
  returned one error of the list at one call, on a kernel with KASAN
  and lockdep under a workload of selftests. For the tagged functions
  of networking, file systems and memory management, about 1 in 180
  ended in a panic, a stall or a lockdep report [#series]_. The kernel
  has no list of such functions by name. Read the function and its
  callers before failing it, and test the upatch on the kernel it
  ships to.
- The scan sees calls, registers and constants. An unlock the compiler
  inlined is a store. A callee that takes the object and returns a
  value, a call through a pointer, a callee without type information, a
  pointer that went through the stack or was loaded from the object:
  none of them counts as work on an argument, and errors behind them
  stay in the list.
- A skip leaves out everything the function does. Reference counts,
  output parameters a caller reads without looking at the result, and
  state the caller expects the function to have advanced are for the
  author of the program to check.
- The list belongs to one build. Compiler, configuration and kernel
  release change which functions are inlined, which errors reach a
  return and which functions are targets. The test VM's kernel lists
  eight errors for ``vfs_fallocate()`` where the build of Figure 3 lists
  nine: it is built without swap, which compiles out the check that
  returns ``-ETXTBSY``. A program that loads on one kernel can be
  refused on the next. A kernel instrumented with outline KASAN or
  KCSAN loses most targets, because each instrumented access is a call
  that takes a pointer and returns nothing.
- A program attaches to the entry of a function. Where the compiler
  inlined the function into a caller, that caller never passes the
  entry, and the program does not run for it.
- A function that returns a pointer, a ``bool`` or nothing is no
  target, and neither is a place inside a function.
- Pointer arguments are not trusted. The program can read through them,
  and such a read tolerates a fault, but kfuncs that require a trusted
  pointer refuse them.
- The kernel skips a run of a tracing program that is already running
  on the same CPU, and the call then goes through as if the program had
  returned 0. :ref:`runs-the-kernel-skips` says when that happens and
  how a task can bring it about. Where an LSM hook covers the
  operation, refuse it in an ``lsm`` program, which the kernel never
  skips.
- The scan exists for x86-64 and arm64. A riscv64 kernel has the
  declared targets only.

Related
-------

- :doc:`fentry-fexit` for the trampoline and the programs that observe a
  call
- :doc:`bpf-lsm` for the hooks the kernel places on purpose
- :doc:`/upatches/write/attach-kinds` for the sections ``shirudo build``
  accepts
- :doc:`/upatches/write/pitfalls` for what a program misses
- :doc:`/upatches/learn/kernel-fix-tutorial` for the way from a fix to a
  upatch

.. [#series] Anton Protopopov and Alexei Starovoitov, `bpf: fmod_ret for
   each function that returns errors
   <https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/commit/?id=3a4161c87e356d33e179076a5194d6f407cda567>`__,
   the bpf-next series that added the scan, with the counts and
   measurements quoted on this page. The talk `Scaling BPF LSM hooks and
   error injection across the kernel
   <https://lpc.events/event/20/contributions/2435/>`__ at the Linux
   Plumbers Conference 2026 gives the background.
