# kernel PWN
专攻Linux下的kernel，从简单的开始入门。</br>
Linux kernel版本会在文章开头处声明。</br>
对应的实际例子或者cve以后再更新。</br>



# how2kernel

- [Linux kernel环境搭建](https://github.com/fangdada/kernelPWN/tree/master/how2kernel/00build_environ)
- [null dereference](https://github.com/fangdada/kernelPWN/tree/master/how2kernel/01null_dereference)
- [stack smashing](https://github.com/fangdada/kernelPWN/tree/master/how2kernel/02stack_smashing)
- [stack ROP](https://github.com/fangdada/kernelPWN/tree/master/how2kernel/03stack_ROP)
- [heap ROP](https://github.com/fangdada/kernelPWN/tree/master/how2kernel/04heap_ROP)
- [addr_limit](https://github.com/fangdada/kernelPWN/tree/master/how2kernel/05addr_limit)
- ...

</br>

# kernel实例

放一些CTF里的内核题，以后也可能会放CVE。</br>

## stack smashing

> 跟常规用户层的栈溢出类似，不同之处在于控制eip为getshell时是从内核态跳转到用户态，需要构造trap_frame结构。

- [CSAW2010 kernel](https://github.com/fangdada/kernelPWN/tree/master/CSAW2010)
- ...

## 待续...

> ....

</br>

# how2pwn

[点这里跳转](https://github.com/fangdada/ctf/tree/master/how2pwn)



