# SVM-Hypervisor
This is a ring0 header framework in order to simplify the creation of hypervisors on SVM
# Usage example
This is a simple example(https://github.com/Nitr0-G/SVM-Hypervisor/tree/main/example/Simple%20example) that builds as follows:
1) Connect the include file Hypervisor.hpp


2) Setting up callbacks for the main changeable structures of the hypervisor


3) Declare (in my case, I wanted to declare a global object) the object, then check the SVM support, call the VirtualizeAllProcessors method.


4) The hypervisor has virtualized the existing system


5) In this example there is no example of unloading, but we can call the DevirtualizeAllProcessors method.

We can inject it, for example, through OSR Loader or through my header library https://github.com/Nitr0-G/DriverLoader

You can also find some macroses for YMM and XMM push in Simple example
# Credits
Inspired by:
1) https://github.com/Nitr0-G/Kernel-Bridge


2) https://github.com/SinaKarvandi/Hypervisor-From-Scratch


3) https://rayanfam.com/topics/hypervisor-from-scratch-part-1/
