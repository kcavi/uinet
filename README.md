# uinet
userspace netstack basic freebsd

用户态协议栈
基于f-stack的修改，源码来自freebsd11，整合多线程模式

编译方法：
直接执行make
默认的ARCH为x86_64，需要修改可以更改lib/machine_include/machine

运行方法：
./example/helloworld -i ens38

ens38为本机的物理接口名

接口要设置为混杂模式，ifconfig ens38 promisc

配置文件在config.ini，可以修改接口ip等参数

测试代码在example/main.c，已完成UDP,TCP，socket，select测试


默认测试方法：直接通过浏览器访问配置文件的ip地址

测试环境：ubuntu18.4

