---
title: thumb指令虚拟化学习(一)
data: 2017-10-24 20:23:30
categories: Android
top: 85
tags:
- 加固
- capstone
---




## 背景
上半年接触过一些 **app加固** 的知识, 对 **vm** 这块一直空有兴趣而没有了解过;  最近, 阅读了几篇文章, `有所启发`, 所以决定学习一下 **vm** 这块的一些操作.

## 阅读资料
[Kcon2017 第五代加固技术ARM VMP原理与应用](https://github.com/knownsec/KCon/blob/master/2017/%5BKCon%202017%5D0827_3_%E9%99%88%E6%84%89%E9%91%AB_%E7%AC%AC%E4%BA%94%E4%BB%A3%E5%8A%A0%E5%9B%BA%E6%8A%80%E6%9C%AFARM%20VMP%E5%8E%9F%E7%90%86%E5%AE%9E%E7%8E%B0%E4%B8%8E%E5%BA%94%E7%94%A8.pdf)
[ARM平台指令虚拟化探索](http://www.cnblogs.com/2014asm/p/6534897.html)


## 环境搭建:
- 需要安装python的capstone模块, 可以直接使用pip安装. (另外: **强烈建议下载capstone源码, 以便随时阅读**.)
```bash
    pip install capstone
```
- ida/radare2 `在本节中, 提取指令的时候会用到`.

- arm官方文档(https://yurichev.com/mirrors/ARMv8-A_Architecture_Reference_Manual_(Issue_A.a).pdf)

## 本篇文章大致分为如下几个部分:

1. 手动提取编译好的可执行文件中的 **你想要加密的函数**, 并转换为 **16进制的格式**.

2. 初步了解 **capstone** 中的 **对Arm指令进行处理的操作函数**.

3. 了解 **thumb指令编码** , `此处研究thumb的原因是: 在提出函数的bytes时, 发现自定义的函数, 都被转换成了thumb指令的格式, 所以笔者先研究thumb;  当然, 要知道, thumb并不是独立于arm存在的, thumb的存在是为了提高效率`.

4. 设计自己的一套 **指令集** , `很简单的一套指令集, 能模拟常见的thumb指令, 例如 push, pop, str, ldr, add, sub, mov, cmp, blx ...`.

5. 写代码, `此处参考了capstone源码中的/bindings/python/capstone/* 中的有关代码, 初学py, 代码写的差, 有什么建议还请多多交流)`.


### 1. 提取指令.

我们提取的是下面程序中的 **judge** 函数.

#### 用ida提取:

我们将会在这篇文章中用到的程序:
```c
#include <stdio.h>

char key[16] = {'a', 'a', 'a', 'a', '1', '1', '1', '1', 'q', 'r', 'c', 'o', 'b', 'g', 's', 'k'};

int judge(const char *s)
{
    int ret = 1;
    char c[16] = {'a', 'b', 'c', 'd', '1', '2', '3', '4', 'q', 's', 'e', 'r', 'b', 'h', 'u', 'n'};
    int i;
    for (i = 0; i < 16; i++)
    {
        switch(i % 4)   
        {
        case 0: 
            if (s[i]  == c[i])
                continue;
            break;  
        case 1:
            if (s[i] + 1 == c[i])
                continue;
            break;
        case 2:
            if (s[i] + 2 == c[i])
                continue;
            break;
        case 3:
            if (s[i] + 3 == c[i])
                continue; 
            break;
        } 
        ret = 0; 
    }
    return ret;
}

int main(int argc, char *argv[])
{
    printf("hello World\n");
    char a[16];
    scanf("%s", a);

    if (judge(a) == 1)
        printf("ok");
    else
        printf("error");

    return 0;
}
```

用ndk-build编译成armv7a可执行程序后, 放入ida中, 用idc脚本提::

idc脚本, start为judge函数的起始地址, end为judge函数的结束地址.

```c
#include <idc.idc>

static main() {
	
	auto start, end, fd, i, inst;
	
	fd = fopen("D:\\idaResult\\armOpcodeByte.txt", "wt+");
	

	start = 0x863c;
	end = 0x86BA;
	
	for(i = start; i < end; i++) {
		inst = Byte(i);
		fprintf(fd, "\\x%02x", inst);
	}
	
	
	fclose(fd);
}
```
提取出来后的结果:

```python
\x1f\x49\xf0\xb5\x79\x44\x09\x68\x87\xb0\x07\x46\x0b\x68\x01\xaa\x0d\x46\x16\x46\x05\x93\x1b\x4b\x7b\x44\x03\xf1\x10\x0e\x18\x68\x08\x33\x53\xf8\x04\x1c\x73\x45\x14\x46\x03\xc4\x22\x46\xf6\xd1\x3a\x46\x00\x23\x01\x20\x03\xf0\x03\x01\x02\x29\x09\xd0\x03\x29\x0a\xd0\x01\x29\x02\xd0\x14\x78\xf1\x5c\x08\xe0\x11\x78\x01\x31\x04\xe0\x11\x78\x02\x31\x01\xe0\x11\x78\x03\x31\xf4\x5c\x01\x33\xa1\x42\x18\xbf\x00\x20\x10\x2b\x02\xf1\x01\x02\xe3\xd1\x05\x9a\x2b\x68\x9a\x42\x01\xd0\xff\xf7\x0a\xef\x07\xb0\xf0\xbd
```


#### 用radare2提取 

'(才发现原来radare2 v2.0都已经发布了)'


`对r2语法不做讲解了, 网上也有了一些文章, 大家可以去看`.  笔者本身也不是很熟悉~

```bash
username-l0phtg@L0phTg:armeabi-v7a$ r2 test
 -- Interpret radare2 scripts with '. <path-to-script>'. Similar to the bash source alias command.
[0x000085a0]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x000085a0]> afl~judge
0x0000863c   17 126          sym.judge
[0x000085a0]> 0x863c
[0x0000863c]> pcp 126
import struct
buf = struct.pack ("126B", *[
0x1f,0x49,0xf0,0xb5,0x79,0x44,0x09,0x68,0x87,0xb0,0x07,
0x46,0x0b,0x68,0x01,0xaa,0x0d,0x46,0x16,0x46,0x05,0x93,
0x1b,0x4b,0x7b,0x44,0x03,0xf1,0x10,0x0e,0x18,0x68,0x08,
0x33,0x53,0xf8,0x04,0x1c,0x73,0x45,0x14,0x46,0x03,0xc4,
0x22,0x46,0xf6,0xd1,0x3a,0x46,0x00,0x23,0x01,0x20,0x03,
0xf0,0x03,0x01,0x02,0x29,0x09,0xd0,0x03,0x29,0x0a,0xd0,
0x01,0x29,0x02,0xd0,0x14,0x78,0xf1,0x5c,0x08,0xe0,0x11,
0x78,0x01,0x31,0x04,0xe0,0x11,0x78,0x02,0x31,0x01,0xe0,
0x11,0x78,0x03,0x31,0xf4,0x5c,0x01,0x33,0xa1,0x42,0x18,
0xbf,0x00,0x20,0x10,0x2b,0x02,0xf1,0x01,0x02,0xe3,0xd1,
0x05,0x9a,0x2b,0x68,0x9a,0x42,0x01,0xd0,0xff,0xf7,0x0a,
0xef,0x07,0xb0,0xf0,0xbd])
[0x0000863c]>
```


### 了解capstone中对arm指令进行操作的函数 `接口`

####   从源代码中提供的`example`, 来初步了解capstone提供给我们的可用的`接口`的使用

我们参考的主要是 `/bindings/python/test_arm.py` 和 `/bindings/python/test_detail.py`这两个文件:

1. test_arm.py   `源代码过多, 这里就不全部都放上来了`

```python
#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
from capstone import *
from capstone.arm import *
from xprint import to_hex, to_x, to_x_32


ARM_CODE = b"\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3\x00\x02\x01\xf1\x05\x40\xd0\xe8\xf4\x80\x00\x00"
THUMB_CODE = b"\x70\x47\x00\xf0\x10\xe8\xeb\x46\x83\xb0\xc9\x68\x1f\xb1\x30\xbf\xaf\xf3\x20\x84"

all_tests = (
        (CS_ARCH_ARM, CS_MODE_ARM, ARM_CODE, "ARM", None),
        (CS_ARCH_ARM, CS_MODE_THUMB, THUMB_CODE, "Thumb", None),
        )


def print_insn_detail(insn):
    # print address, mnemonic and operands
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

    # "data" instruction generated by SKIPDATA option has no detail
    if insn.id == 0:
        return

    if len(insn.operands) > 0:
        print("\top_count: %u" % len(insn.operands))
        c = 0
        for i in insn.operands:
            if i.type == ARM_OP_REG:
                print("\t\toperands[%u].type: REG = %s" % (c, insn.reg_name(i.reg)))
            if i.type == ARM_OP_IMM:
                print("\t\toperands[%u].type: IMM = 0x%s" % (c, to_x_32(i.imm)))
...............................
            if i.type == ARM_OP_MEM:
                print("\t\toperands[%u].type: MEM" % c)
                if i.mem.base != 0:
                    print("\t\t\toperands[%u].mem.base: REG = %s" \
                        % (c, insn.reg_name(i.mem.base)))
                if i.mem.index != 0:
                    print("\t\t\toperands[%u].mem.index: REG = %s" \
                        % (c, insn.reg_name(i.mem.index)))
                if i.mem.scale != 1:
                    print("\t\t\toperands[%u].mem.scale: %u" \
                        % (c, i.mem.scale))
                if i.mem.disp != 0:
                    print("\t\t\toperands[%u].mem.disp: 0x%s" \
                        % (c, to_x_32(i.mem.disp)))
...............................
            c += 1

    if insn.update_flags:
        print("\tUpdate-flags: True")
    if insn.writeback:
        print("\tWrite-back: True")
    if not insn.cc in [ARM_CC_AL, ARM_CC_INVALID]:
        print("\tCode condition: %u" % insn.cc)
...............................


# ## Test class Cs
def test_class():

    for (arch, mode, code, comment, syntax) in all_tests:
        print("*" * 16)
        print("Platform: %s" % comment)
        print("Code: %s" % to_hex(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)
            if syntax:
                md.syntax = syntax
            md.detail = True
            for insn in md.disasm(code, 0x80001000):
                print_insn_detail(insn)
                print ()
            print ("0x%x:\n" % (insn.address + insn.size))
        except CsError as e:
            print("ERROR: %s" % e)


if __name__ == '__main__':
    test_class()
```

观察`test_arm.py`, 我们可以看到的重要的一些操作有:

```python
md = Cs(arch, mode)
for insn in md.disasm(code, 0x80001000):
    print_insn_detail(insn)
```
首先通过`md = Cs(arch, mode)`来选择我们的架构, 然后调用`md.disasm`返回 指令(insn) (这里Cs.disasm就是一个生成器, 参看py语法)
然后打印`insn`的细节(助记符, 操作数, 以及每个操作数的类型等)

打印的时候(这里我只列举了部分操作):
- 我们可以发现 **针对指令** 调用了 **insn.address**, **insn.mnemonic**,  **insn.op_str**, **insn.operands**, **insn.update_flags**, **insn.cc**.....
- 针对 **操作数** 调用了 **i.type**, **i.reg**, **i.mem**....


2. test_detail.py (省略了一些和上面test_arm.py相似的代码)

```python
..........
def print_detail(insn):
    print("0x%x:\t%s\t%s  // insn-ID: %u, insn-mnem: %s" \
        % (insn.address, insn.mnemonic, insn.op_str, insn.id, \
        insn.insn_name()))

    # "data" instruction generated by SKIPDATA option has no detail
    if insn.id == 0:
        return

    if len(insn.regs_read) > 0:
        print("\tImplicit registers read: ", end=''),
        for m in insn.regs_read:
            print("%s " % insn.reg_name(m), end=''),
        print()

    if len(insn.regs_write) > 0:
        print("\tImplicit registers modified: ", end=''),
        for m in insn.regs_write:
            print("%s " % insn.reg_name(m), end=''),
        print()

    if len(insn.groups) > 0:
        print("\tThis instruction belongs to groups: ", end=''),
        for m in insn.groups:
            print("%s " % insn.group_name(m), end=''),
        print()``
        ....................................

```
操作很明显:
**insn.regs_read**, **insn.regs_write**, **insn.groups**.

####




####   观察源代码中的`/bindings/python/capstone/__init__.py`来了解**CS** 和 CSIN的实现:


















