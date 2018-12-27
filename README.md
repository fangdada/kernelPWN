# kernelPWN
专攻Linux下的kernel，从简单的开始入门。</br>
这是一个从32位Linux-2.6.32.1版本的kernel开始学习与记录的how2kernel。</br>
对应的实际例子或者cve以后再更新。</br>



# how2kernel

- [Linux kernel环境搭建](https://github.com/fangdada/kernelPWN/tree/master/00build_environ)
- [null dereference](https://github.com/fangdada/kernelPWN/tree/master/01null_dereference)
- [stack smashing](https://github.com/fangdada/kernelPWN/tree/master/02stack_smashing)
- ...

</br>

# kernel实例

放一些CTF里的内核题，以后也可能会放CVE。</br>

## stack smashing

> 跟常规用户层的栈溢出类似，不同之处在于控制eip为getshell时是从内核态跳转到用户态，需要构造trap_frame结构。

- [CSAW2010 kernel](https://github.com/fangdada/kernelPWN/tree/master/CSAW2010)
- ...

## ....

> ....

# how2pwn

[点这里跳转](https://github.com/fangdada/ctf/tree/master/how2pwn)



