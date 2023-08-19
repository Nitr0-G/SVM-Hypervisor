# SVM-Hypervisor
This is a ring0 header/source framework in order to simplify the creation of hypervisors on SVM
# Usage example
This is a simple example(https://github.com/Nitr0-G/SVM-Hypervisor/tree/main/example/Simple%20example) that builds as follows:

    Connect the include file Hypervisor.hpp

    Setting up callbacks for the main changeable structures of the hypervisor

    Declare (in my case, I wanted to declare a global object) the object, then check the SVM support, call the VirtualizeAllProcessors method.

    The hypervisor has virtualized the existing system

    In this example there is no example of unloading, but we can call the DevirtualizeAllProcessors method.

We can inject it, for example, through OSR Loader or through my header library https://github.com/Nitr0-G/DriverLoader
