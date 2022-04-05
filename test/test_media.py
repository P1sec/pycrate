# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : test/test_media.py
# * Created : 2016-03-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from timeit import timeit

from pycrate_core.elt    import Element
from pycrate_media.BMP   import BMP
from pycrate_media.PNG   import PNG
from pycrate_media.JPEG  import JPEG
from pycrate_media.TIFF  import TIFF
from pycrate_media.GIF   import GIF
from pycrate_media.MPEG4 import MPEG4
from pycrate_media.MP3   import MP3


def test_bmp(path):
    fd = open(path, 'rb')
    f_bmp = fd.read()
    fd.close()
    
    BMP._GEN = BMP._GEN_LBUF
    bmp = BMP()
    bmp.from_bytes(f_bmp)
    bmp.reautomate()
    assert( bmp.to_bytes() == f_bmp )
    BMP._GEN = BMP._GEN_LPIX
    bmp = BMP()
    bmp.from_bytes(f_bmp)
    bmp.reautomate()
    assert( bmp.to_bytes() == f_bmp )
    
def test_png(path):
    fd = open(path, 'rb')
    f_png = fd.read()
    fd.close()
    
    png = PNG()
    png.from_bytes(f_png)
    png.reautomate()
    assert( png.to_bytes() == f_png )

def test_jpeg(path):
    fd = open(path, 'rb')
    f_jpg = fd.read()
    fd.close()
    
    jpeg = JPEG()
    jpeg.from_bytes(f_jpg)
    jpeg.reautomate()
    assert( jpeg.to_bytes() == f_jpg )

def test_tiff(path):
    fd = open(path, 'rb')
    f_tiff = fd.read()
    fd.close()
    
    tiff = TIFF()
    tiff.from_bytes(f_tiff)
    tiff.reautomate()
    assert( tiff.to_bytes() == f_tiff )

def test_gif(path):
    fd = open(path, 'rb')
    f_gif = fd.read()
    fd.close()
    
    gif = GIF()
    gif.from_bytes(f_gif)
    gif.reautomate()
    assert( gif.to_bytes() == f_gif )

def test_mp4(path):
    fd = open(path, 'rb')
    f_mp4 = fd.read()
    fd.close()
    
    mp4 = MPEG4()
    mp4.from_bytes(f_mp4)
    mp4.reautomate()
    assert( mp4.to_bytes() == f_mp4 )

def test_mp3(path):
    fd = open(path, 'rb')
    f_mp3 = fd.read()
    fd.close()
    
    mp3 = MP3()
    mp3.from_bytes(f_mp3)
    mp3.reautomate()
    assert( mp3.to_bytes() == f_mp3 )

def test_perf_media(bmp_path,
                    png_path,
                    jpg_path,
                    tiff_path,
                    gif_path,
                    mp4_path,
                    mp3_path):
    
    fd = open(bmp_path, 'rb')
    f_bmp = fd.read()
    fd.close()
    
    def test_bmp(f_bmp=f_bmp, fmt=BMP):
        bmp = BMP()
        bmp.from_bytes(f_bmp)
    
    print('[+] instantiating and parsing BMP in LBUF mode')
    BMP._GEN = BMP._GEN_LBUF
    Ta = timeit(test_bmp, number=1000)
    print('test_bmp: {0:.4f}'.format(Ta))
    
    bmp = BMP()
    bmp.from_bytes(f_bmp)
    bmp.reautomate()
    print('[+] regenerating BMP in LBUF mode')
    Tb = timeit(bmp.to_bytes, number=1000)
    print('bmp.to_bytes: {0:.4f}'.format(Tb))
    
    print('[+] instantiating and parsing BMP in LPIX mode')
    BMP._GEN = BMP._GEN_LPIX
    Tc = timeit(test_bmp, number=15)
    print('test_bmp: {0:.4f}'.format(Tc))
    
    bmp = BMP()
    bmp.from_bytes(f_bmp)
    bmp.reautomate()
    print('[+] regenerating BMP in LPIX mode')
    Td = timeit(bmp.to_bytes, number=10)
    print('bmp.to_bytes: {0:.4f}'.format(Td))
    
    
    fd = open(png_path, 'rb')
    f_png = fd.read()
    fd.close()
    
    def test_png(f_png=f_png):
        png = PNG()
        png.from_bytes(f_png)
    
    print('[+] instantiating and parsing PNG')
    Te = timeit(test_png, number=1000)
    print('test_png: {0:.4f}'.format(Te))
    
    png = PNG()
    png.from_bytes(f_png)
    png.reautomate()
    print('[+] regenerating PNG')
    Tf = timeit(png.to_bytes, number=1600)
    print('png.to_bytes: {0:.4f}'.format(Tf))
    
    
    fd = open(jpg_path, 'rb')
    f_jpg = fd.read()
    fd.close()
    
    def test_jpg(f_jpg=f_jpg):
        jpeg = JPEG()
        jpeg.from_bytes(f_jpg)
    
    print('[+] instantiating and parsing JPEG')
    Tg = timeit(test_jpg, number=150)
    print('test_png: {0:.4f}'.format(Tg))
    
    jpeg = JPEG()
    jpeg.from_bytes(f_jpg)
    jpeg.reautomate()
    print('[+] regenerating JPEG')
    Th = timeit(jpeg.to_bytes, number=300)
    print('jpeg.to_bytes: {0:.4f}'.format(Th))
    
    
    fd = open(tiff_path, 'rb')
    f_tiff = fd.read()
    fd.close()
    
    def test_tiff(f_tiff=f_tiff):
        tiff = TIFF()
        tiff.from_bytes(f_tiff)
    
    print('[+] instantiating and parsing TIFF')
    Ti = timeit(test_tiff, number=250)
    print('test_tiff: {0:.4f}'.format(Ti))
    
    tiff = TIFF()
    tiff.from_bytes(f_tiff)
    tiff.reautomate()
    print('[+] regenerating TIFF')
    Tj = timeit(tiff.to_bytes, number=800)
    print('tiff.to_bytes: {0:.4f}'.format(Tj))
    
    
    fd = open(gif_path, 'rb')
    f_gif = fd.read()
    fd.close()
    
    def test_gif(f_gif=f_gif):
        gif = GIF()
        gif.from_bytes(f_gif)
    
    print('[+] instantiating and parsing GIF')
    Tk = timeit(test_gif, number=70)
    print('test_gif: {0:.4f}'.format(Tk))
    
    gif = GIF()
    gif.from_bytes(f_gif)
    gif.reautomate()
    print('[+] regenerating GIF')
    Tl = timeit(gif.to_bytes, number=60)
    print('gif.to_bytes: {0:.4f}'.format(Tl))
    
    
    fd = open(mp4_path, 'rb')
    f_mp4 = fd.read()
    fd.close()
    
    def test_mp4(f_mp4=f_mp4):
        mp4 = MPEG4()
        mp4.from_bytes(f_mp4)
    
    print('[+] instantiating and parsing MPEG4')
    Tm = timeit(test_mp4, number=60)
    print('test_mp4: {0:.4f}'.format(Tm))
    
    mp4 = MPEG4()
    mp4.from_bytes(f_mp4)
    mp4.reautomate()
    print('[+] regenerating MPEG4')
    Tn = timeit(mp4.to_bytes, number=200)
    print('mp4.to_bytes: {0:.4f}'.format(Tn))
    
    
    fd = open(mp3_path, 'rb')
    f_mp3 = fd.read()
    fd.close()
    
    def test_mp3(f_mp3=f_mp3):
        mp3 = MP3()
        mp3.from_bytes(f_mp3)
    
    print('[+] instantiating and parsing MP3')
    To = timeit(test_mp3, number=300)
    print('test_mp3: {0:.4f}'.format(To))
    
    mp3 = MP3()
    mp3.from_bytes(f_mp3)
    mp3.reautomate()
    print('[+] regenerating MP3')
    Tp = timeit(mp3.to_bytes, number=700)
    print('mp3.to_bytes: {0:.4f}'.format(Tp))
    
    print('[+] test_media total time: {0:.4f}'\
          .format(Ta+Tb+Tc+Td+Te+Tf+Ti+Tj+Tk+Tl+Tm+Tn+To+Tp))


if __name__ == '__main__':
    test_perf_media('./test/res/bmp_test.bmp',
                    './test/res/xkcd_wireless_signal.png',
                    './test/res/ESP8266.jpg',
                    './test/res/xkcd_phone_2.tiff',
                    './test/res/nyancat.gif',
                    './test/res/Simulation_of_Kepler_Supernova_Explosion.mp4',
                    './test/res/snare.mp3'
                    )

