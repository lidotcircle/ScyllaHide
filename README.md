## ScyllaMonitor

fork from [ScyllaHide](https://github.com/x64dbg/ScyllaHide)

### Repository Structure

- [Scylla](./Scylla) 主要的库, 包含了 Scylla 的主要功能
- [ScyllaGUI](./ScyllaGUI) 对应Scylla功能的GUI, 使用[Dear ImGui](https://github.com/ocornut/imgui)构建界面
- [ScyllaStandalone](./ScyllaStandalone) ScyllaMonitor的 exe 可执行文件版本
- [InjectorCLI](./InjectorCLI) ScyllaMonitor的命令行版本
- [asplugin](./asplugin) ScyllaMonitor的插件版本
  - [x64dbg](./asplugin/x64dbg) x64dbg插件
- [sexchange](./sexchange) 用在DLL注入的数据结构, 注入的DLL可以通过这个结构来获取ScyllaMonitor日志UDP端口、配置等信息
- [slogger](./slogger) ScyllaMonitor的日志系统
- [smalloc](./smalloc) 基于VirtualAlloc的简单内存分配器, 由于内存注入的DLL无法初始化vcrt, 所以需要用这个库。所以编写用于内存注入的DLL时, 使用这个库的函数分配内存, 例子见[MonitorLibrary](./MonitorLibrary)。
- [sutils](./sutils) 常用的工具函数
- [HookLibrary](./HookLibrary) 包含反反调试Hook函数的DLL, 来自[ScyllaHide](https://github.com/x64dbg/ScyllaHide/HookLibrary), 这个库内置在ScyllaMonitor中 
- [MonitorLibrary](./MonitorLibrary) 一些系统函数的Hook函数, 待完善, 这个库也内置在ScyllaMonitor中
- [ScyllaTest](./ScyllaTest) 测试用的 exe 可执行文件, 用来测试ScyllaMonitor的功能, PEB反反调试
- [3rdparty](./3rdparty) 第三方库


### Build

使用CMake构建生成工具, 需要安装Visual Studio, 使用nmake进行构建  
**注意:** 构建前需要拉取所有的子仓库

``` bash
$ vcvars32           # or vcvars64 for 64bit version
$ mkdir build && cd build
$ cmake -G"NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ..
$ nmake
```
