# uinet
userspace netstack basic freebsd

用户态协议栈
基于f-stack的修改，源码来自freebsd11，整合多线程模式

编译方法：
直接执行make
默认的ARCH为x86_64，需要修改可以更改lib/machine_include/machine

运行方法：
example/helloworld -i eth0

eth0为本机的物理接口名

测试代码在example/main.c
