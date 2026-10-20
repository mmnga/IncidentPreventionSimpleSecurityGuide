"""Render trusted documentation diagrams, never execute example application code.

Development-only dependency: Pillow. The audit skill remains standard-library only.
All text/coordinates/data live in diagrams.json; SVG stays editable and PNG is 2x.
"""
import argparse
import base64
from html import escape
import hashlib
import json
import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
W, H = 1600, 1120
COLORS = {
    'ink': '#172f3c', 'muted': '#536c7a', 'bg': '#f3f6f7',
    'line': '#426174', 'code': '#087f78', 'config': '#2b61af', 'model': '#a96916',
    'code_bg': '#e5f5f1', 'config_bg': '#eaf1fd', 'model_bg': '#fff1d9',
}
LABELS = {'code': '参照コード', 'config': '設定・ひな形', 'model': '未接続・未実施'}


class Canvas:
    def __init__(self, scale, regular, bold):
        self.scale, self.regular, self.bold = scale, regular, bold
        self.image = Image.new('RGB', (W * scale, H * scale), COLORS['bg'])
        self.draw = ImageDraw.Draw(self.image)
        self.svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img">']
        self.fonts = {}
        self.rect(0, 0, W, H, COLORS['bg'], radius=0)

    def font(self, size, bold=False):
        key = (size, bold)
        if key not in self.fonts:
            self.fonts[key] = ImageFont.truetype(self.bold if bold else self.regular, int(size * self.scale))
        return self.fonts[key]

    def width(self, text, size, bold=False):
        return self.font(size, bold).getlength(text) / self.scale

    def wrap(self, text, width, size, bold=False):
        lines = []
        for paragraph in text.split('\n'):
            line = ''
            for char in paragraph:
                if line and self.width(line + char, size, bold) > width:
                    lines.append(line)
                    line = char
                else:
                    line += char
            lines.append(line)
        return lines

    def text(self, x, y, value, size=21, color=None, bold=False):
        color = color or COLORS['ink']
        self.draw.text((round(x * self.scale), round(y * self.scale)), value,
                       fill=color, font=self.font(size, bold), anchor='lt')
        weight = '600' if bold else '400'
        self.svg.append(f'<text x="{x}" y="{y + size * .9:.2f}" font-family="Hiragino Kaku Gothic ProN,Hiragino Sans,Noto Sans CJK JP,Meiryo,sans-serif" font-size="{size}" font-weight="{weight}" fill="{color}">{escape(value)}</text>')

    def multiline(self, x, y, value, width, size, lineheight, maximum=None, bold=False, color=None):
        lines = self.wrap(value, width, size, bold)
        if maximum is not None and len(lines) > maximum:
            raise ValueError(f'Text overflow: {value!r}: {len(lines)} > {maximum}')
        for i, line in enumerate(lines):
            self.text(x, y + i * lineheight, line, size, color, bold)
        return len(lines) * lineheight

    def rect(self, x, y, w, h, fill, stroke=None, radius=16):
        s = self.scale
        self.draw.rounded_rectangle([round(x*s), round(y*s), round((x+w)*s), round((y+h)*s)],
            radius=radius*s, fill=fill, outline=stroke, width=2*s if stroke else 1)
        self.svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}"' +
                        (f' stroke="{stroke}" stroke-width="2"' if stroke else '') + '/>')

    def line(self, points, color, dashed=False, width=3):
        s = self.scale
        if dashed:
            for (x1,y1),(x2,y2) in zip(points, points[1:]):
                distance = math.hypot(x2-x1,y2-y1)
                if not distance:
                    continue
                for start in range(0, math.ceil(distance), 16):
                    end = min(start + 9, distance)
                    self.draw.line([(round((x1+(x2-x1)*start/distance)*s), round((y1+(y2-y1)*start/distance)*s)),
                                    (round((x1+(x2-x1)*end/distance)*s), round((y1+(y2-y1)*end/distance)*s))],
                                   fill=color, width=width*s)
        else:
            self.draw.line([(round(x*s),round(y*s)) for x,y in points], fill=color, width=width*s)
        dash = ' stroke-dasharray="9 7"' if dashed else ''
        self.svg.append('<polyline points="'+' '.join(f'{x},{y}' for x,y in points)+f'" fill="none" stroke="{color}" stroke-width="{width}" stroke-linejoin="round"{dash}/>')

    def arrow(self, edge):
        points = edge['points']
        color = COLORS['model'] if edge.get('planned') else COLORS['line']
        self.line(points, color, edge.get('planned', False))
        x,y = points[-1]
        px,py = points[-2]
        angle = math.atan2(y-py,x-px)
        triangle = [(x,y), (x-12*math.cos(angle)+6*math.sin(angle), y-12*math.sin(angle)-6*math.cos(angle)),
                    (x-12*math.cos(angle)-6*math.sin(angle), y-12*math.sin(angle)+6*math.cos(angle))]
        self.draw.polygon([(round(a*self.scale),round(b*self.scale)) for a,b in triangle], fill=color)
        self.svg.append('<polygon points="'+' '.join(f'{a:.2f},{b:.2f}' for a,b in triangle)+f'" fill="{color}"/>')
        if edge.get('label'):
            tx,ty = edge['label_at']
            textwidth = self.width(edge['label'], 17)
            self.rect(tx-textwidth/2-9,ty-5,textwidth+18,29,'#ffffff',radius=6)
            self.text(tx-textwidth/2,ty,edge['label'],17,color)

    def card(self, card):
        x,y,w,h = card['box']
        kind = card['kind']
        color = COLORS[kind]
        self.rect(x,y,w,h,'#ffffff',stroke=color)
        labelwidth = self.width(LABELS[kind],14,True) + 20
        self.rect(x+18,y+15,labelwidth,28,COLORS[kind+'_bg'],radius=7)
        self.text(x+28,y+21,LABELS[kind],14,color,True)
        titleheight = self.multiline(x+20,y+58,card['title'],w-40,25,32,maximum=2,bold=True)
        body_y = y+58+titleheight+13
        body = self.wrap(card['body'],w-40,21)
        if body_y+len(body)*29 > y+h-12:
            raise ValueError('Card overflow: '+card['id']+' / '+card['title'])
        self.multiline(x+20,body_y,card['body'],w-40,21,29)

    def render(self, spec, destination):
        self.svg += [f'<title>{escape(spec["title"])}</title>',f'<desc>{escape(spec["summary"])}</desc>']
        self.text(48,31,'ATLAS NOTES  /  合成アプリのアーキテクチャ',17,COLORS['muted'],True)
        self.text(48,69,spec['number']+'  '+spec['title'],42,bold=True)
        self.multiline(48,128,spec['subtitle'],1504,22,30,maximum=1,color=COLORS['muted'])
        for lane in spec.get('lanes',[]):
            x,y,w,h = lane['box']
            self.rect(x,y,w,h,'#e8eef1',radius=18)
            self.text(x+18,y+12,lane['title'],18,COLORS['muted'],True)
        for edge in spec.get('edges',[]):
            self.arrow(edge)
        for card in spec['cards']:
            self.card(card)
        self.rect(48,905,1504,82,'#ffffff',radius=12)
        self.text(67,919,'この図の要点',17,COLORS['code'],True)
        self.text(245,919,spec['takeaway'],19,bold=True)
        self.text(67,953,'残る確認・接続',17,COLORS['model'],True)
        self.text(245,953,spec['remaining'],18,COLORS['muted'])
        for i,kind in enumerate(('code','config','model')):
            x=48+i*220
            self.rect(x,1004,205,34,COLORS[kind+'_bg'],radius=8)
            self.text(x+13,1013,LABELS[kind],16,COLORS[kind],True)
        self.line([(740,1021),(804,1021)],COLORS['line'])
        self.text(819,1013,'ソース上の参照・処理',16,COLORS['muted'])
        self.line([(1080,1021),(1144,1021)],COLORS['model'],True)
        self.text(1159,1013,'設計上の接続・未実施',16,COLORS['muted'])
        self.text(48,1053,'図は合成ソースの説明です。参照コード・設定の存在は、動作確認や監査PASSを意味しません。',17,COLORS['muted'])
        source_text='確認先: '+'  /  '.join(spec['sources'][:2])
        self.text(48,1085,source_text,14,COLORS['muted'])
        self.svg.append('</svg>')
        png=destination/(spec['id']+'.png')
        svg=destination/(spec['id']+'.svg')
        self.image.save(png,format='PNG',optimize=True)
        svg.write_text('\n'.join(self.svg)+'\n',encoding='utf-8')
        return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (png,svg)}


def make_html(specs, out):
    nav=''.join(f'<a href="#{escape(s["id"])}">{s["number"]} {escape(s["title"])}</a>' for s in specs)
    sections=[]
    for s in specs:
        image_data = 'data:image/png;base64,' + base64.b64encode((out/'images'/(s['id']+'.png')).read_bytes()).decode('ascii')
        sources=''.join('<li><a href="../../'+escape(p)+'">'+escape(p)+'</a></li>' for p in s['sources'])
        sections.append(f'<section id="{escape(s["id"])}"><h2>{s["number"]} {escape(s["title"])}</h2>'
            f'<p>{escape(s["summary"])}</p><a class="picture" href="images/{s["id"]}.png">'
            f'<img loading="lazy" width="1600" height="1120" src="{image_data}" alt="{escape(s["title"]+"。"+s["summary"])}"></a>'
            f'<div class="links"><a href="images/{s["id"]}.png">PNGを開く・拡大</a><a download href="images/{s["id"]}.png">PNGを保存</a>'
            f'<a href="images/{s["id"]}.svg">SVG</a><a href="#top">一覧へ</a></div>'
            f'<p><strong>要点：</strong>{escape(s["takeaway"])}</p><p><strong>残る確認：</strong>{escape(s["remaining"])}</p>'
            f'<details><summary>確認元のファイル</summary><ul>{sources}</ul></details></section>')
    content='''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Atlas Notes — アーキテクチャ図</title><style>
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#f3f6f7;color:#172f3c;font:16px/1.8 system-ui,-apple-system,sans-serif}main{max-width:1600px;margin:auto;padding:40px 24px}h1{font-size:clamp(26px,4vw,42px);line-height:1.4}h2{line-height:1.5}a{color:#126e85;text-underline-offset:3px}header p{max-width:1000px}.tag{display:inline-block;background:#e5f5f1;color:#087f78;padding:3px 12px;border-radius:8px;font-weight:600}.note{background:#fff1d9;padding:14px 20px;border-radius:10px}nav{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin:32px 0 44px}nav a{display:block;background:white;padding:14px 18px;border:1px solid #d6e2e7;border-radius:10px;text-decoration:none}nav a:hover{border-color:#087f78}section{background:white;border-radius:16px;padding:24px;margin-bottom:32px;scroll-margin-top:20px}section h2{margin-top:0}.picture{display:block}img{display:block;width:100%;height:auto;border:1px solid #e3eaed;border-radius:10px}.links{display:flex;gap:22px;flex-wrap:wrap;margin:14px 0}details{padding:12px 16px;background:#f3f6f7;border-radius:10px}summary{cursor:pointer}li a{overflow-wrap:anywhere}@media(max-width:600px){main{padding:24px 12px}section{padding:16px 10px}.links{gap:14px}nav{grid-template-columns:1fr}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}@media print{nav,.links{display:none}section{break-before:page;break-inside:avoid}main{padding:0}section{padding:0}}
</style></head><body><main id="top"><header><span class="tag">合成アプリの設計資料</span><h1>Atlas Notes のアーキテクチャ</h1><p>Web・API・モバイル・通知・外部連携・AI・インフラ・配布・運用を10枚で説明します。緑は参照コード、青は設定・ひな形、黄は未接続・未実施です。実線はソース上の参照・処理、破線は設計上の接続を示します。</p><p class="note">Web・Flutterの既定は通信しないメモリ内デモです。APIはSQLiteを使い、TerraformのRDSとは未接続です。全図が合成ソースの説明で、実配備・動作検証や全220項目の合格証拠ではありません。</p><p>画像を選ぶと拡大できます。スマートフォンでは開いた画像をピンチで拡大してください。</p></header>'''
    (out/'index.html').write_text(content+'<nav aria-label="構成図の一覧">'+nav+'</nav>'+''.join(sections)+'</main></body></html>\n',encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--font',default='/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc')
    parser.add_argument('--bold-font',default='/System/Library/Fonts/ヒラギノ角ゴシック W6.ttc')
    parser.add_argument('--scale',type=int,choices=(1,2,3),default=2)
    args=parser.parse_args()
    if not Path(args.font).is_file() or not Path(args.bold_font).is_file():
        parser.error('Pass local Japanese font files with --font / --bold-font')
    specs=json.loads((BASE/'diagrams.json').read_text(encoding='utf-8'))
    images=BASE/'images'; images.mkdir(exist_ok=True)
    manifest={'kind':'DOCUMENTATION_ASSETS_NOT_AUDIT_EVIDENCE','dimensions':[W*args.scale,H*args.scale],
              'spec_sha256':hashlib.sha256((BASE/'diagrams.json').read_bytes()).hexdigest(),'images':{},'sources':{}}
    catalog=json.loads((ROOT/'skills/repository-security-audit/references/checks.json').read_text())
    check_ids={row['id'] for row in catalog}
    for spec in specs:
        assert set(spec['checks']) <= check_ids
        for source in spec['sources']:
            p=ROOT/source
            assert p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(ROOT/'examples/apps')
            manifest['sources'][source]=hashlib.sha256(p.read_bytes()).hexdigest()
        canvas=Canvas(args.scale,args.font,args.bold_font)
        manifest['images'].update(canvas.render(spec,images))
    make_html(specs,BASE)
    (BASE/'assets.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'Rendered {len(specs)} diagrams as PNG + SVG; no example code was imported.')


if __name__=='__main__':
    main()
