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

### Configuration

配置文件 [scylla.yaml](./Scylla/scylla.yaml) 是个 YAML 文件, 主要分为几个模块, 下面简要说明比较重要的


#### DLL Injection

DLL 注入模块可以选择多个 DLL 文件进行注入, 可选的方式是 *远程线程注入* 和 *内存注入*.
远程线程注入在调试中, 或者在所有线程暂停(WIN7, WIN10可以 FIXME)时不可用,
内存注入不能运行DLL的初始化函数, 所以DLL中的初始化数据结构会处于不正确的状态.

#### Inline Hook

inline hook 支持正则表达式进行导出符号的指定, 当然一个正则表达式应该只匹配到DLL导出符号中的一个.  
有三种语法格式:
``` yaml
ntdll::NtClose: antiant.dll::HookedNtClose  # 1. 导出符号
ntdll::NtClose: antiant.dll$0x333000        # 2. RVA
ntdll::NtClose: antiant.dll#0x22000         # 3. 文件偏移, 暂未实现
```

可以分模块指定:
``` yaml
ntdll.dll:
  NtClose: antianti.dll::HookedNtClose
kernel32.dll:
  OutputDebugStringA: antianti.dll::HookedOutputDebugStringA
```

可以直接指定内存地址
``` yaml
0x100000: 0x343333
```

Hook 的数据会被写入到 注入的DLL中, DLL可以用这些数据获得 Hook 的 Trampoline 函数(原始语义), 用法见 [MonitorLibrary](./MonitorLibrary)
