#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Copyright (C) 2024, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

# 导入所需模块
from dataclasses import dataclass  # 用于创建数据类
from random import randint         # 用于生成随机整数

# 导入项目版本信息
from wafw00f import __version__


@dataclass
class Color:
    """ANSI颜色代码类，用于终端彩色输出"""
    # 白色
    W: str = '\033[1;97m'
    # 黄色
    Y: str = '\033[1;93m'
    # 绿色
    G: str = '\033[1;92m'
    # 红色
    R: str = '\033[1;91m'
    # 蓝色
    B: str = '\033[1;94m'
    # 青色
    C: str = '\033[1;96m'
    # 结束颜色代码
    E: str = '\033[0m'

    @classmethod
    def disable(cls):
        """禁用所有颜色输出"""
        cls.W = ''
        cls.Y = ''
        cls.G = ''
        cls.R = ''
        cls.B = ''
        cls.C = ''
        cls.E = ''

    @classmethod
    def unpack(cls):
        """解包并返回颜色值
        用于简化使用，例如：
        (W,Y,G,R,B,C,E) = Color.unpack()
        """
        return (
            cls.W,
            cls.Y,
            cls.G,
            cls.R,
            cls.B,
            cls.C,
            cls.E
        )


def randomArt():
    # 终端颜色设置
    (W,Y,G,R,B,C,E) = Color.unpack()

    # Woof ASCII艺术字
    woof = '''
                   '''+W+'''______
                  '''+W+'''/      \\
                 '''+W+'''(  Woof! )
                  '''+W+r'''\  ____/                      '''+R+''')
                  '''+W+''',,                           '''+R+''') ('''+Y+'''_
             '''+Y+'''.-. '''+W+'''-    '''+G+'''_______                 '''+R+'''( '''+Y+'''|__|
            '''+Y+'''()``; '''+G+'''|==|_______)                '''+R+'''.)'''+Y+'''|__|
            '''+Y+'''/ ('        '''+G+r'''/|\                  '''+R+'''(  '''+Y+'''|__|
        '''+Y+'''(  /  )       '''+G+r''' / | \                  '''+R+'''. '''+Y+'''|__|
         '''+Y+r'''\(_)_))      '''+G+r'''/  |  \                   '''+Y+'''|__|'''+E+'''

                    '''+C+'~ WAFW00F : '+B+'v'+__version__+''' ~'''+W+'''
    The Web Application Firewall Fingerprinting Toolkit
    '''+E

    # W00f ASCII艺术字
    w00f = '''
                '''+W+'''______
               '''+W+'''/      \\
              '''+W+'''(  W00f! )
               '''+W+r'''\  ____/
               '''+W+''',,    '''+G+'''__            '''+Y+'''404 Hack Not Found
           '''+C+'''|`-.__   '''+G+'''/ /                     '''+R+''' __     __
           '''+C+'''/"  _/  '''+G+'''/_/                       '''+R+r'''\ \   / /
          '''+B+'''*===*    '''+G+'''/                          '''+R+r'''\ \_/ /  '''+Y+'''405 Not Allowed
         '''+C+'''/     )__//                           '''+R+r'''\   /
    '''+C+'''/|  /     /---`                        '''+Y+'''403 Forbidden
    '''+C+r'''\\/`   \ |                                 '''+R+'''/ _ \\
    '''+C+r'''`\    /_\\_              '''+Y+'''502 Bad Gateway  '''+R+r'''/ / \ \  '''+Y+'''500 Internal Error
      '''+C+'''`_____``-`                             '''+R+r'''/_/   \_\\

                        '''+C+'~ WAFW00F : '+B+'v'+__version__+''' ~'''+W+'''
        The Web Application Firewall Fingerprinting Toolkit
    '''+E

    # Wo0f ASCII艺术字
    wo0f = r'''
                 ?              ,.   (   .      )        .      "
         __        ??          ("     )  )'     ,'        )  . (`     '`
    (___()'`;   ???          .; )  ' (( (" )    ;(,     ((  (  ;)  "  )")
    /,___ /`                 _"., ,._'_.,)_(..,( . )_  _' )_') (. _..( ' )
    \\   \\                 |____|____|____|____|____|____|____|____|____|

                                ~ WAFW00F : v'''+__version__+''' ~
                    ~ Sniffing Web Application Firewalls since 2014 ~
'''

    # 将所有艺术字放入列表中
    arts = [woof, w00f, wo0f]
    # 随机返回一个艺术字
    return arts[randint(0, len(arts)-1)]