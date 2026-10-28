"""Render the static social preview with Pillow: python3 scripts/create_share_image.py."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
SCALE = 2
im = Image.new('RGB', (1200*SCALE, 630*SCALE), '#07150f')
d = ImageDraw.Draw(im)
def font(size, bold=False):
    return ImageFont.truetype('/usr/share/fonts/truetype/noto/NotoSans-' + ('Bold' if bold else 'Regular') + '.ttf', size*SCALE)
def text(x,y,value,size,color,bold=False):
    d.text((x*SCALE,y*SCALE),value,font=font(size,bold),fill=color)
def box(rect,color,radius=16,outline=None,width=1):
    d.rounded_rectangle(tuple(v*SCALE for v in rect),radius*SCALE,fill=color,outline=outline,width=width*SCALE)
def line(points,color,width=4):
    d.line([(x*SCALE,y*SCALE) for x,y in points],fill=color,width=width*SCALE)
box((1,1,1198,628),'#0a1b14',26,'#2c5140',2)
text(56,36,'BLAKE2b  /  FORKMONITOR',18,'#75dba4',True)
text(56,84,'180-day coinbase maturity',48,'#edf9f2',True)
text(58,158,'Live chain monitoring · September split history',24,'#a8c5b5')
line([(58,224),(1140,224)],'#284c3b',1)
# A schematic branch diagram, without claiming a current live split.
line([(120,390),(430,390),(580,310),(1000,310)],'#467b60',5)
line([(430,390),(580,458),(1000,458)],'#92733b',5)
for x,y in [(120,390),(320,390),(620,310),(830,310),(1040,310)]:
    box((x-43,y-43,x+43,y+43),'#2fc27d',14)
for x,y in [(620,458),(830,458)]:
    box((x-43,y-43,x+43,y+43),'#e6b952',14)
text(58,554,'lukecoin.zndtoshi.com',22,'#c3e1ce',True)
box((980,555,1141,591),'#133a27',16)
d.ellipse((996*SCALE,568*SCALE,1006*SCALE,578*SCALE),fill='#6df7ae')
text(1016,559,'LIVE WATCH',14,'#8cf0b5',True)
im.resize((1200,630),Image.Resampling.LANCZOS).save(ROOT/'dist'/'social-preview.png',optimize=True)
