---
title: elf文件格式和AndroidLinker加载.so的源码分析
date: 2017-03-19 23:27:30
categories: Android
tags:
 - 文件格式
 - Android源码
---
#
最近在学习android应用的加壳和混淆方法, 所以遇到了一些有关.so是如何加载到android中去的问题, 看了一些视频和文章, 所以想在此总结一下.
首先我们先分析一下elf的文件格式, 然后再分析linker的源码.

## elf文件格式
本文只对elf文件格式进行简单的分析, 如果要进行深入的了解, 推荐`<<程序员的自我修养>>`中第3章.
/usr/includ/elf.h中定义了elf文件头结构和相关的常数.
分析elf文件时, 建议使用`010 editor`这款十六进制编辑软件, 运行elf模板后可以清晰的将文件格式显示出来, 大致的显示是(坑, 此处应该用图片的)
```c
				NAME                           Value            Start       Size		Color		Comment
	struct file                                                 0h          109Ch
		struct elf_header                                       0h          34h
		struct program_header_table                             34h         120h
		struct section_header_table                             1B274h      460h
		struct dynamic_symbol_table                             18Ch        F10h
```
可以看到, 一个elf文件中包含一个header, 3个table, 我们一个一个的来分析一下.
首先分析`Elf header`, 它位于每一个elf文件开始的地方:
```c
typedef struct                                                            typedef struct
{                                                                         {
	unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */     unsigned char e_ident[EI_NIDENT];
	Elf32_Half    e_type;         /* Object file type */                  	Elf64_Half    e_type;     
	Elf32_Half    e_machine;      /* Architecture */                      	Elf64_Half    e_machine;  
	Elf32_Word    e_version;      /* Object file version */               	Elf64_Word    e_version;  
	Elf32_Addr    e_entry;        /* Entry point virtual address */       	Elf64_Addr    e_entry;    
	Elf32_Off e_phoff;        /* Program header table file offset */      	Elf64_Off e_phoff;        
	Elf32_Off e_shoff;        /* Section header table file offset */      	Elf64_Off e_shoff;        
	Elf32_Word    e_flags;        /* Processor-specific flags */          	Elf64_Word    e_flags;    
	Elf32_Half    e_ehsize;       /* ELF header size in bytes */          	Elf64_Half    e_ehsize;   
	Elf32_Half    e_phentsize;        /* Program header table entry size */	Elf64_Half    e_phentsize;
	Elf32_Half    e_phnum;        /* Program header table entry count */  	Elf64_Half    e_phnum;    
	Elf32_Half    e_shentsize;        /* Section header table entry size */	Elf64_Half    e_shentsize;
	Elf32_Half    e_shnum;        /* Section header table entry count */  	Elf64_Half    e_shnum;    
	Elf32_Half    e_shstrndx;     /* Section header string table index */ 	Elf64_Half    e_shstrndx; 
} Elf32_Ehdr;                                                              } Elf64_Ehdr;
```
可以看到, header中包含了magic number, 文件类型, 目标文件版本, 入口地址(如果为0, 说明此文件为可重定位文件), program header的开始地址(即为在so文件中的offset), section header的开始地址, 标志位, elf头本身的大小, program header和section header的size和数量, 最后是section header中string section在section中的下标.(用010 editor可以看到清楚的看到一个.so文件包含众多的program header 和 section header, 这两个段在做.so混淆时会经常分析)

现在分析`program header`
```c
/* Program segment header.  */

typedef struct														typedef struct
{                                                                   {
	Elf32_Word    p_type;         /* Segment type */                	Elf64_Word    p_type;   
	Elf32_Off p_offset;       /* Segment file offset */             	Elf64_Off p_offset;     
	Elf32_Addr    p_vaddr;        /* Segment virtual address */     	Elf64_Addr    p_vaddr;  
	Elf32_Addr    p_paddr;        /* Segment physical address */    	Elf64_Addr    p_paddr;  
	Elf32_Word    p_filesz;       /* Segment size in file */        	Elf64_Word    p_filesz; 
	Elf32_Word    p_memsz;        /* Segment size in memory */      	Elf64_Word    p_memsz;  
	Elf32_Word    p_flags;        /* Segment flags */               	Elf64_Word    p_flags;  
	Elf32_Word    p_align;        /* Segment alignment */           	Elf64_Word    p_align;  
} Elf32_Phdr;														} Elf64_Phdr;
```

接下来分析`section header`, section相信了解过汇编的同学都非常熟悉了, 这个section header里面就存放了我们elf中各个段的信息.
看一下section header段描述符的结构:(64位的与32位的结构体大致相同, 只是把类型改为了Elf64的类型)
```c
typedef struct
{
	Elf32_Word    sh_name;        /* Section name (string tbl index) 段名*/
    Elf32_Word    sh_type;        /* Section type 段类型*/
	Elf32_Word    sh_flags;       /* Section flags 标志位*/
	Elf32_Addr    sh_addr;        /* Section virtual addr at execution 段虚拟地址*/
	Elf32_Off sh_offset;          /* Section file offset 段偏移*/
	Elf32_Word    sh_size;        /* Section size in bytes 段的长度*/
	Elf32_Word    sh_link;        /* Link to another section 段的链接信息*/
	Elf32_Word    sh_info;        /* Additional section information 段链接的相关信息*/
	Elf32_Word    sh_addralign;   /* Section alignment 段地址对齐*/
	Elf32_Word    sh_entsize;     /* Entry size if section holds table 项的长度*/
} Elf32_Shdr;
```
最后分析动态符号表(`symbol table`):
```c
typedef struct
{
  	Elf32_Word    st_name;        /* Symbol name (string tbl index) */
	Elf32_Addr    st_value;       /* Symbol value */
	Elf32_Word    st_size;        /* Symbol size */
	unsigned char st_info;        /* Symbol type and binding */
	unsigned char st_other;       /* Symbol visibility */
	Elf32_Section st_shndx;       /* Section index */
} Elf32_Sym;
```
包含的信息有符号名, 符号相对应的值, 符号大小, 符号类型和绑定信息, 符号所在的段.

## Android Linker加载.so的源码分析
Android中的本地文件.so是通过Linker加载到内存中去并且执行的.(本文分析的源码为Android4.4.4)
				---- 推荐一款好用的源码阅读工具 source Insight
```cpp
java层:  System.LoadLibrary("function");
native:			--->  Dalvik/vm/native/java_lang_Runtime.cpp: Dalvik_java_lang_Runtime_nativeLoad 
						--->Dalvik/vm/Native.cpp: dvmLoadNativeCode(const char* fileName, Object* ClassLoader, char** reason)
								--->bionic/linker/dlfcn.c: dlopen(const char* pathName, RTLD_LAZY)
									 	--->bionic/linker/linker.cpp: do_dlopen(const char* name, int flags)
```
1.  核心函数为`do_dlopen`: 
```cpp
soinfo* do_dlopen(const char* name, int flags) {  // 函数的参数为
	if ((flags & ~(RTLD_NOW|RTLD_LAZY|RTLD_LOCAL|RTLD_GLOBAL)) != 0) {
		DL_ERR("invalid flags to dlopen: %x", flags);
		return NULL;
	}
	set_soinfo_pool_protection(PROT_READ | PROT_WRITE);	// 设置so信息池的访问权限为可读可写
	soinfo* si = find_library(name);					// 找到name函数, 装载so, 并返回指向.soinfo的指针
	if (si != NULL) {
				      si->CallConstructors();			// 初始化so库
	}
	set_soinfo_pool_protection(PROT_READ);				// 设置so信息池的访问权限为只读
	return si;
}
```
2. 查看`find_library`函数可以发现它调用了`find_library_internal`函数, 
```cpp
static soinfo* find_library(const char* name) {
	soinfo* si = find_library_internal(name);
	if (si != NULL) {
		si->ref_count++;
	}
	return si;
}
```
分析`find_library_internal`函数, 发现其主要调用了`load_library()`函数和 `soinfo_link_image()` 函数.
_
```cpp
static soinfo* find_library_internal(const char* name) {
	if (name == NULL) {
		return somain;
	}
	soinfo* si = find_loaded_library(name);			// 判断.so是否完全加载, 如果加载: 返回有效的指针;如果没有加载, 返回null;
	if (si != NULL) {								// 如果已经加载，返回
		if (si->flags & FLAG_LINKED) {
			return si;
		}
		DL_ERR("OOPS: recursive link to \"%s\"", si->name);
		return NULL;
	}

	TRACE("[ '%s' has not been loaded yet.  Locating...]", name);  // 打印so还没有加载
	si = load_library(name);		// 加载.so
	if (si == NULL) {
		return NULL;
	}
	// At this point we know that whatever is loaded @ base is a valid ELF
	// shared library whose segments are properly mapped in.
	TRACE("[ init_library base=0x%08x sz=0x%08x name='%s' ]",
			si->base, si->size, si->name);

	if (!soinfo_link_image(si)) {		// 完成.so的重定位
		munmap(reinterpret_cast<void*>(si->base), si->size);
		soinfo_free(si);
		return NULL;
	}
	return si;
}
```

分析`load_library`函数, 会找到elf_read.`Load()`方法, 这个方法就是load
```cpp
static soinfo* load_library(const char* name) {
// Open the file.
	int fd = open_library(name);						// 打开文件, 获取fd
	if (fd == -1) {
		DL_ERR("library \"%s\" not found", name);
		return NULL;
	}

	// Read the ELF header and load the segments.
	ElfReader elf_reader(name, fd);						// 初始化elfReader对象
	if (!elf_reader.Load()) {							// 通过elfReader对象的Load()方法, 将so文件装载到内存
		return NULL;
	}

	const char* bname = strrchr(name, '/');
	soinfo* si = soinfo_alloc(bname ? bname + 1 : name);	// 分配so_info结构, 并按照装载结果更新相应的成员变量
	if (si == NULL) {
		return NULL;
	}
	si->base = elf_reader.load_start();
	si->size = elf_reader.load_size();
	si->load_bias = elf_reader.load_bias();
	si->flags = 0;
	si->entry = 0;
	si->dynamic = NULL;
	si->phnum = elf_reader.phdr_count();
	si->phdr = elf_reader.loaded_phdr();

	return si;
}

这里放一个ElfReader结构:
class ElfReader {
public:
	ElfReader(const char* name, int fd);
	~ElfReader();

	bool Load();

	size_t phdr_count() { return phdr_num_; }
	Elf32_Addr load_start() { return reinterpret_cast<Elf32_Addr>(load_start_); }
	Elf32_Addr load_size() { return load_size_; }
	Elf32_Addr load_bias() { return load_bias_; }
	const Elf32_Phdr* loaded_phdr() { return loaded_phdr_; }

private:
	bool ReadElfHeader();
	bool VerifyElfHeader();
	bool ReadProgramHeader();
	bool ReserveAddressSpace();
	bool LoadSegments();
	bool FindPhdr();
	bool CheckPhdr(Elf32_Addr);	

	const char* name_;
	int fd_;	

	Elf32_Ehdr header_;
	size_t phdr_num_;	

	void* phdr_mmap_;
	Elf32_Phdr* phdr_table_;
	Elf32_Addr phdr_size_;	

	// First page of reserved address space.
	void* load_start_;
	// Size in bytes of reserved address space.
	Elf32_Addr load_size_;
	// Load bias.
	Elf32_Addr load_bias_;

	// Loaded phdr.
	const Elf32_Phdr* loaded_phdr_;
};
```

这里是`Load()`函数
```cpp
bool ElfReader::Load() {
	return ReadElfHeader() &&					// 读取
		VerifyElfHeader() &&				// 验证
		ReadProgramHeader() &&				// 读取Program header
		ReserveAddressSpace() &&			// 根据Program header计算so需要的内存size并分配相应的空间
		LoadSegments() &&					// 将so按照segment为单位装载到内存
		FindPhdr();						// on 装载到内存的so中找到program header, 方便以后链接过程use
}
```
 * 首先是`ReadElfHeader`()函数, 发现其是直接调用`read`函数读取到header中的.
```cpp
bool ElfReader::ReadElfHeader() {
	ssize_t rc = TEMP_FAILURE_RETRY(read(fd_, &header_, sizeof(header_)));	// use read() function 直接将elfheader读取到header中
	```//////////////////////////////
	return true;
}
```
 * 然后是`VerifyElfread`()函数, 对Elfheader进行验证识别: 是否为32位，大小端，类型和版本.
 * 之后`ReadProgramHeader`()函数(加载program header table从elf文件到一个只读的私有匿名的mmap-ed block中):
```cpp
bool ElfReader::ReadProgramHeader() {
	phdr_num_ = header_.e_phnum;										
	//  将program header on内存中中单独映射一份, use于解析时临时use, on so装载到内存后, 便会释放这块内存, 转而使use装载后的so中的program header

	// Like the kernel, we only accept program header tables that
	// are smaller than 64KiB.
	if (phdr_num_ < 1 || phdr_num_ > 65536/sizeof(Elf32_Phdr)) {
		DL_ERR("\"%s\" has invalid e_phnum: %d", name_, phdr_num_);
		return false;
	}

	Elf32_Addr page_min = PAGE_START(header_.e_phoff);
	Elf32_Addr page_max = PAGE_END(header_.e_phoff + (phdr_num_ * sizeof(Elf32_Phdr)));
	Elf32_Addr page_offset = PAGE_OFFSET(header_.e_phoff);	

	phdr_size_ = page_max - page_min;

	void* mmap_result = mmap(NULL, phdr_size_, PROT_READ, MAP_PRIVATE, fd_, page_min);
		if (mmap_result == MAP_FAILED) {
		DL_ERR("\"%s\" phdr mmap failed: %s", name_, strerror(errno));
		return false;
	}

	phdr_mmap_ = mmap_result;
	phdr_table_ = reinterpret_cast<Elf32_Phdr*>(reinterpret_cast<char*>(mmap_result) + page_offset);
	return true;
}
```
 * `ReverveAddressSpace`()函数(准备虚拟内存足够的大来存放Program header中的`Load`段(两个Load段～～) 通过`mmap with PROT_NONE` 实现

```cpp
bool ElfReader::ReserveAddressSpace() {
	Elf32_Addr min_vaddr;
	load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);	// 获取so on 内存中需要的空间load_size
	if (load_size_ == 0) {
	      DL_ERR("\"%s\" has no loadable segments", name_);
		      return false;
	}

	uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);
	void* start = mmap(addr, load_size_, PROT_NONE, mmap_flags, -1, 0);			// use mmap匿名映射, 预留出相应的空间
	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
	if (start == MAP_FAILED) {
		DL_ERR("couldn't reserve %d bytes of address space for \"%s\"", load_size_, name_);
		return false;
	}

	load_start_ = start;
	load_bias_ = reinterpret_cast<uint8_t*>(start) - addr;				// so可以指定加载的基址, 但是so指定的加载基址可能不是页对齐的, 这种情况
	return true;															// 会导致实际映射地址和指定的加载地址有一个偏差, 这个偏差便是load_bias
}
```
 * `LoadSegments`()函数(在进程地址空间中加载所有可加载的段(假设你已经预留了空间为这个library)):
```cpp
bool ElfReader::LoadSegments() {	
  	for (size_t i = 0; i < phdr_num_; ++i) {
	const Elf32_Phdr* phdr = &phdr_table_[i];	// 遍历program header table

	if (phdr->p_type != PT_LOAD) {			// 加载所有p_type == PT_LOAD的段
		continue;
	}

	``` 之后就是一些设置段地址，段偏移, 之后mmap的一些操作

	return true;
}

```

 * `FindPhdr`()(返回program header table加载到内存中的地址, 因为之后还要执行.so的重定位).
现在回到我们`find_library_internal`()这里，在执行完load_library()之后, 还有一个重要的函数为 `soinfo_link_image`(soinfo* si):

```cpp
这个函数会完成.so的动态链接，其中包含我们加载的.so库的重定位过程:
 1. 定位动态section,将动态section的虚拟地址和项数和读写权限存在dynamic, dynamic_count, dynamic_flags中.
	size_t dynamic_count;
	Elf32_Word dynamic_flags;
	phdr_table_get_dynamic_section(phdr, phnum, base, &si->dynamic,		// 定位dynamic section
	                                   &dynamic_count, &dynamic_flags);		// 

 2. 解析Dynamic section
 3. 调用find_library, 返回所有依赖的.so的soinfo指针并存放在数组中.
 4. 重定位(处理plt_rel(延迟绑定)和rel):
 	可以看到, 处理两个重定位表的函数都是soinfo_relocate函数.
    if (si->plt_rel != NULL) {
		DEBUG("[ relocating %s plt ]", si->name );
		if (soinfo_relocate(si, si->plt_rel, si->plt_rel_count, needed)) {
			return false;
		}
	}
	if (si->rel != NULL) {
		DEBUG("[ relocating %s ]", si->name );
		if (soinfo_relocate(si, si->rel, si->rel_count, needed)) {		 
			return false;
		}
	}		
```
  现在分析soinfo_relocate函数
```cpp













```
