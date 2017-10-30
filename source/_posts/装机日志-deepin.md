---
title: 装机日志-deepin
data: 2017-20-28 11:47:58
categories: life
tags:
- 日常生活
---

## 背景
最近一直在码代码和写.md, 深刻体会到在windows上办公有多么艰难. 安装了一下`spacevim/neovim`后, 意识到了高效率的办公会给人带来很大的乐趣. 所以, 在遇到了很多与环境配置相关的问题(却解决不了之后), 毅然决定更换系统.
## 选择
犹豫了一天到底是该装`Ubuntu16.04`还是`deepin`(`导致上课前, 忘了给舍友刷卡...`).最终还是经不住deepin`绚丽的UI设计`的诱惑, 决定尝试一下`deepin`.(**没错, 颜值在我心中就是这么重要**)

## 装机过程
装机过程很简单, 下载好官方的镜像源, 之后检验一下**md5**.
```bash
$checksum  

```
然后用**官方的启动盘制作工具**把U盘装入deepin, 重启时插入U盘, 设置为U盘启动就可以了.

**重点来了**, 因为我不想用windows10了, 所以直接把系统装在c盘中, 因为原来的系统有**3个分区, 所以装机时不用格式化 D 盘 和 E 盘**(`我的E盘有7/8个虚拟机文件, 在装好deepin后, 依然可以正常使用`)

装机总结: 
- deepin系统装入c盘.   
- D盘, E盘可以不用格式化.(当然, 如果电脑里没啥重要文件的, skip it)

## 下来就是激动人心的时刻了

先放几张图:

桌面
{% asset_img desktop.png 桌面%}

分屏
{% asset_img splitScreen.png 分屏 %}

我们最爱的vim
{% asset_img vimMarkdownPreview.png vimMarkdown %}

当然, 还有很多其它的不错的设计, 这里就不多放图了.

### 配置nvim/spacevim

依赖项:
- python支持: 建议先`pip install neovim`和`pip3 install neovim`.
- font支持: (读者可以自行查看readme进行安装) git地址: `https://github.com/powerline/fonts.git` , 用来更好的显示vim界面(字体, 状态栏...).
- tagbar支持: 安装 `ctags`.

```
sudo apt install ctags
```

**安装**:

- neovim安装: `sudo apt install neovim`
- Spacevim安装: (读者可以自行查看readme进行安装) git地址: `https://github.com/SpaceVim/SpaceVim`



- init.nvim(来, 放出我们的口号: **打造属于自己的编辑器**, 这个文件是用户配置文件, 读者可以自行配置)

我这里只是对自己的需求进行了简单的配置:

1. 配置markdown预览:(因为它默认预览采用的插件是`iamcoo/MarkdownPreview.vim`, 所以根据该插件作者的说明进行配置)

- 默认预览浏览器为`google-chrome`:
```
let g:mkdp_path_to_chrome = 'google-chrome'
```

- 映射预览为`F4`:
```bash
nmap <silent> <F4> <Plug>MarkdownPreview        " for normal mode
imap <silent> <F4> <Plug>MarkdownPreview        " for insert mode
```

2.  设置状态栏分隔符为箭头:
```
let g:spacevim_statusline_separator = 'arrow'
```

### 配置zsh/oh-my-zsh

1. 安装zsh
```
sudo apt install zsh
```

2. 安装oh-my-zsh

```
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
```
具体的配置看个人喜好.

### 安装tools
https://github.com/PikachuHy/...       `一位大佬写的net工具,  大家懂得`


## 总结

总之, `deepin`还是带给我很大的惊喜的.  `deepin终端`, `深度截图`, 还可以愉快的使用网络, 开心的在linux下办公hahahahaha.

