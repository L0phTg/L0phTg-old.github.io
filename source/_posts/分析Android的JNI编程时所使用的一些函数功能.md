---
title: 分析Android的JNI编程时所使用的一些函数功能
date: 2017-03-16 03:07:59
categories: Android
tags:
 - JNI
 - Android
---

## 基本类型
<jni.h>文件存放的位置在\Android\sdk\ndk-bundle\platforms\android-24\arch-arm\usr\include\jni.h

现在来看一下jni.h头文件中内容:
	
``` cpp
	class _jobject {};										typedef _jobject*       jobject;
	class _jclass : public _jobject {};						typedef _jclass*        jclass;       	
	class _jstring : public _jobject {};                    typedef _jstring*       jstring;
	class _jarray : public _jobject {};                     typedef _jarray*        jarray;
	class _jobjectArray : public _jarray {};                typedef _jobjectArray*  jobjectArray;
	class _jbooleanArray : public _jarray {};               typedef _jbooleanArray* jbooleanArray;
	class _jbyteArray : public _jarray {};                  typedef _jbyteArray*    jbyteArray;
	class _jcharArray : public _jarray {};                  typedef _jcharArray*    jcharArray;
	class _jshortArray : public _jarray {};                 typedef _jshortArray*   jshortArray;
	class _jintArray : public _jarray {};                   typedef _jintArray*     jintArray;
	class _jlongArray : public _jarray {};                  typedef _jlongArray*    jlongArray;
	class _jfloatArray : public _jarray {};                 typedef _jfloatArray*   jfloatArray;
	class _jdoubleArray : public _jarray {};                typedef _jdoubleArray*  jdoubleArray;
	class _jthrowable : public _jobject {};					typedef _jthrowable*    jthrowable;
```
从右边的typedef可以看出,每一个Jni中的cpp类型都有一个Java中的类型与之相对应.

这里我们重点分析经常看到的_JNIEnv,_JavaVM,JNIEnv,JavaVM
```cpp
struct _JNIEnv;
struct _JavaVM;
typedef const struct JNINativeInterface* C_JNIEnv;

#if defined(__cplusplus)
typedef _JNIEnv JNIEnv;
typedef _JavaVM JavaVM;
#else
typedef const struct JNINativeInterface* JNIEnv;
typedef const struct JNIInvokeInterface* JavaVM;
#endif
```
JNINativeInterface为Native层的接口函数指针表, Jni中的本地函数通过这些接口来调用java层的函数.
/_JNIEnv是一个object, 包含一个指向JNINativeInterface的指针变量function和一些接口函数.
JNIEnv在cpp中的定义为_JNIEnv, 在c中的定义为 struct JNINativeInterface*.
JNIEnv: 每一个线程中都有一个属于自己线程的env, 且只在创建自己的线程内有效, 不能跨线程传递.
下面分析JavaVM:
```	c
struct _JavaVM {										                       struct JNIInvokeInterface {			                                       
    const struct JNIInvokeInterface* functions;                                 void*       reserved0;
                                                                               	void*       reserved1;
																				void*       reserved2;
	#if defined(__cplusplus)                                                   	       
	jint DestroyJavaVM()                                                       
	{ return functions->DestroyJavaVM(this); }                                 	jint        (*DestroyJavaVM)(JavaVM*);
	jint AttachCurrentThread(JNIEnv** p_env, void* thr_args)                   	jint        (*AttachCurrentThread)(JavaVM*, JNIEnv**, void*);
	{ return functions->AttachCurrentThread(this, p_env, thr_args); }          	jint        (*DetachCurrentThread)(JavaVM*);
	jint DetachCurrentThread()                                                 	jint        (*GetEnv)(JavaVM*, void**, jint);
	{ return functions->DetachCurrentThread(this); }                           	jint        (*AttachCurrentThreadAsDaemon)(JavaVM*, JNIEnv**, void*);
	jint GetEnv(void** env, jint version)                                      };
	{ return functions->GetEnv(this, env, version); }
	jint AttachCurrentThreadAsDaemon(JNIEnv** p_env, void* thr_args)
	{ return functions->AttachCurrentThreadAsDaemon(this, p_env, thr_args); }
	#endif /*__cplusplus*/
};
```
JavaVM在cpp中定义为_JavaVM, 在c中定义为指向JNIInvokeInterface的指针.
JavaVM只有一个, 因为它是java虚拟机在Jni中的表示.


在用ida加载.apk中.so文件时会发现识别出来的native函数是这样的:
```
	int __fastcall Java_com_njctf_mobile_easycrack_MainActivity_parseText(int a1, int a2, int a3);
```
java层的函数调用是这样的:
```
	public native String parseText(String arg1); 
```
而这里的a1就是我们的env, a2就是jobject或者jclass, a3就是String arg1了.
我们在导入<jni.h>头文件和添加了Structures之后, 就可以对ida中的参数类型和参数名字进行修改了.

修改之后的结果:
```
int __fastcall Java_com_njctf_mobile_easycrack_MainActivity_parseText(_JNIEnv *env, jobject *obj, jstring inputString);
```

