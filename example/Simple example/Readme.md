# Simple example

This is a simple example that builds as follows:
1) Connect the include file Hypervisor.hpp


2) Setting up callbacks for the main changeable structures of the hypervisor


3) Declare (in my case, I wanted to declare a global object) the object, then check the SVM support, call the VirtualizeAllProcessors method.


4) The hypervisor has virtualized the existing system


5) In this example there is no example of unloading, but we can call the DevirtualizeAllProcessors method.

We can inject it, for example, through OSR Loader or through my header library https://github.com/Nitr0-G/DriverLoader
