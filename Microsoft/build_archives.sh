#!/bin/bash
ar cqT x.a arch/x86/built-in.a arch/x86/kernel/ebda.o arch/x86/kernel/head_64.o arch/x86/kernel/head64.o arch/x86/kernel/platform-quirks.o arch/x86/lib/built-in.a arch/x86/lib/lib.a arch/x86/pci/built-in.a block/built-in.a certs/built-in.a crypto/built-in.a drivers/built-in.a fs/built-in.a init/built-in.a ipc/built-in.a kernel/built-in.a lib/built-in.a lib/lib.a mm/built-in.a net/built-in.a security/built-in.a sound/built-in.a usr/built-in.a virt/built-in.a 

ll arch/x86/built-in.a
ll arch/x86/kernel/ebda.o
ll arch/x86/kernel/head_64.o
ll arch/x86/kernel/head64.o
ll arch/x86/kernel/platform-quirks.o
ll arch/x86/lib/built-in.a
ll arch/x86/lib/lib.a
ll arch/x86/pci/built-in.a
ll block/built-in.a
ll certs/built-in.a
ll crypto/built-in.a
ll drivers/built-in.a
ll fs/built-in.a
ll init/built-in.a
ll ipc/built-in.a
ll kernel/built-in.a
ll lib/built-in.a
ll lib/lib.a
ll mm/built-in.a
ll net/built-in.a
ll security/built-in.a
ll sound/built-in.a
ll usr/built-in.a
ll virt/built-in.a


for lib in `find -name '*.a'`;
    do ar -t $lib | xargs ar rvs $lib.new && mv -v $lib.new $lib;
done

ar -t x.a | xargs ar rvs x.new && mv -v x.new x.a