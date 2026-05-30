# Exp-F 对抗性完备性:同一被禁 op 经各 syscall 向量(1=检测, 0=漏)

audit 模式;AGENT 经 `actplane run` 注入。**目的:覆盖是设计使然(我们 hook 了这些向量),
并诚实点名真实漏洞,而非让它们以静默漏检藏起来。**

| 被禁 op | 向量 | 检测 |
|---|---|:---:|
| write | open/openat (`echo >`) | 1 |
| write | **openat2** (raw) | 1 |
| write | **creat** | 1 |
| write | **truncate** | 1 |
| write | 裸 C openat | 1 |
| write(unlink) | unlink/unlinkat | 1 |
| write(rename) | rename/renameat2 | 1 |
| exec | execve | 1 |
| exec | **execveat** (fd) | 1 |
| write | **io_uring** OPENAT (async) | 1 |

## 新增 hook(本轮补)
openat2 / creat / truncate 之前未 hook,经此可被绕过;现已加 `tp/syscalls/sys_enter_*`
(openat2 从 `struct open_how` 读 flags;creat/truncate 视为写)。exec 经 `sched_process_exec`
捕获**所有** exec 系统调用(execve/execveat 同源),故 execveat 自然命中。

## 关于 io_uring(如实)
上表 io_uring OPENAT 在本机内核(6.15)**被检测到**(文件确被创建且违规触发)。我们**未加**
io_uring 专用 hook——这是内核把该 OPENAT 走到了被我们 hook 的路径上,属**附带命中**,不保证
跨内核成立。稳健做法仍是 io_uring 专用 tracepoint 或 BPF-LSM(`file_open` 对任何打开路径都触发)。

## 诚实记录的真实边界(本机 tracepoint 模式,未测为覆盖)
- **fd-only 变体**(ftruncate / fchmod / 经已打开 fd 的 write / mmap 写):tracepoint 模式只见 fd,
  无路径解析;LSM(file_truncate / file_permission / mmap_file)可覆盖,待 BPF-LSM。
- **UDP 无连接外发**(sendto/sendmsg)与 `*at` 链接族(linkat/symlinkat):未 hook,列为待补。
- 这些是**设计层已知边界**,在此明列——不让它们以静默漏检藏起来。已覆盖向量见上表(10/10)。
