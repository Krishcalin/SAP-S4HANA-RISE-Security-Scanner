"""
Minimal PPTX (PowerPoint / OOXML) writer — standard library only.
==================================================================
Builds a valid Office Open XML presentation (.pptx = a ZIP of XML parts) with
no third-party dependencies, mirroring the project's hand-rolled `pdf_writer`.
Supports filled rectangles (sharp or rounded), multi-paragraph text boxes with
per-run styling, and embedded PNG/JPEG images.

Coordinates are EMUs (914400 per inch); use the Inches()/Pt() helpers. The
default slide is 16:9 widescreen (13.333in x 7.5in).
"""
import zipfile
from typing import List, Dict, Any, Optional

EMU_PER_INCH = 914400


def Inches(v: float) -> int:
    return int(round(v * EMU_PER_INCH))


def Pt(v: float) -> int:
    # font sizes are in hundredths of a point in DrawingML
    return int(round(v * 100))


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


class _Shape:
    pass


class Slide:
    def __init__(self, writer: "PPTXWriter"):
        self.writer = writer
        self._ops: List[str] = []
        self._next_id = 2  # 1 is the group shape
        self.images: List[str] = []  # media file paths, in order; rel = image index

    # ── rectangle ──
    def rect(self, x, y, w, h, fill: Optional[str] = None, line: Optional[str] = None,
             line_w: float = 1.0, round_: bool = False):
        sid = self._next_id
        self._next_id += 1
        geom = "roundRect" if round_ else "rect"
        fill_xml = (f'<a:solidFill><a:srgbClr val="{fill}"/></a:solidFill>'
                    if fill else "<a:noFill/>")
        if line:
            ln = (f'<a:ln w="{Inches(line_w / 72.0)}"><a:solidFill>'
                  f'<a:srgbClr val="{line}"/></a:solidFill></a:ln>')
        else:
            ln = '<a:ln><a:noFill/></a:ln>'
        av = '<a:avLst><a:gd name="adj" fmla="val 8000"/></a:avLst>' if round_ else '<a:avLst/>'
        self._ops.append(
            f'<p:sp><p:nvSpPr><p:cNvPr id="{sid}" name="rect{sid}"/><p:cNvSpPr/>'
            f'<p:nvPr/></p:nvSpPr><p:spPr>'
            f'<a:xfrm><a:off x="{int(x)}" y="{int(y)}"/><a:ext cx="{int(w)}" cy="{int(h)}"/></a:xfrm>'
            f'<a:prstGeom prst="{geom}">{av}</a:prstGeom>{fill_xml}{ln}</p:spPr>'
            f'<p:txBody><a:bodyPr/><a:lstStyle/><a:p/></p:txBody></p:sp>'
        )

    # ── text box ──
    def text(self, x, y, w, h, paras: List[Dict[str, Any]], anchor: str = "t",
             wrap: bool = True, fill: Optional[str] = None,
             l_ins: float = 0.06, t_ins: float = 0.03):
        """paras: list of {"runs":[{"t","sz","b","i","color","font"}], "align",
        "bullet", "space_before"} — 'align' in l/ctr/r; sizes in points."""
        sid = self._next_id
        self._next_id += 1
        body_paras = []
        for p in paras:
            align = p.get("align", "l")
            spc = p.get("space_before", 0)
            spc_xml = f'<a:spcBef><a:spcPts val="{int(spc * 100)}"/></a:spcBef>' if spc else ""
            bullet = ('<a:buFont typeface="Arial"/><a:buChar char="&#8226;"/>'
                      if p.get("bullet") else "<a:buNone/>")
            indent = ' marL="182880" indent="-182880"' if p.get("bullet") else ""
            runs = []
            for r in p["runs"]:
                b = ' b="1"' if r.get("b") else ""
                it = ' i="1"' if r.get("i") else ""
                color = r.get("color", "1F2933")
                font = r.get("font", "Calibri")
                runs.append(
                    f'<a:r><a:rPr lang="en-US" sz="{Pt(r.get("sz", 18))}"{b}{it}>'
                    f'<a:solidFill><a:srgbClr val="{color}"/></a:solidFill>'
                    f'<a:latin typeface="{font}"/></a:rPr><a:t>{_esc(r["t"])}</a:t></a:r>'
                )
            if not runs:
                runs.append('<a:endParaRPr lang="en-US"/>')
            body_paras.append(
                f'<a:p><a:pPr algn="{align}"{indent}>{spc_xml}{bullet}</a:pPr>{"".join(runs)}</a:p>'
            )
        wrap_attr = 'wrap="square"' if wrap else 'wrap="none"'
        fill_xml = (f'<a:solidFill><a:srgbClr val="{fill}"/></a:solidFill>'
                    if fill else "")
        self._ops.append(
            f'<p:sp><p:nvSpPr><p:cNvPr id="{sid}" name="tx{sid}"/><p:cNvSpPr txBox="1"/>'
            f'<p:nvPr/></p:nvSpPr><p:spPr>'
            f'<a:xfrm><a:off x="{int(x)}" y="{int(y)}"/><a:ext cx="{int(w)}" cy="{int(h)}"/></a:xfrm>'
            f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>{fill_xml}</p:spPr>'
            f'<p:txBody><a:bodyPr {wrap_attr} anchor="{anchor}" '
            f'lIns="{Inches(l_ins)}" tIns="{Inches(t_ins)}" rIns="{Inches(l_ins)}" '
            f'bIns="{Inches(t_ins)}"><a:normAutofit/></a:bodyPr><a:lstStyle/>'
            f'{"".join(body_paras)}</p:txBody></p:sp>'
        )

    # ── image (png/jpeg) ──
    def image(self, x, y, w, h, path: str):
        self.images.append(path)
        rid = "rIdImg%d" % len(self.images)
        sid = self._next_id
        self._next_id += 1
        self._ops.append(
            f'<p:pic><p:nvPicPr><p:cNvPr id="{sid}" name="img{sid}"/>'
            f'<p:cNvPicPr><a:picLocks noChangeAspect="1"/></p:cNvPicPr><p:nvPr/></p:nvPicPr>'
            f'<p:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></p:blipFill>'
            f'<p:spPr><a:xfrm><a:off x="{int(x)}" y="{int(y)}"/>'
            f'<a:ext cx="{int(w)}" cy="{int(h)}"/></a:xfrm>'
            f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic>'
        )

    def _xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
            'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            '<p:cSld><p:spTree>'
            '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
            '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
            '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
            + "".join(self._ops) +
            '</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>'
        )


class PPTXWriter:
    def __init__(self, w_in: float = 13.333, h_in: float = 7.5,
                 title: str = "Presentation", author: str = "PhalanxCyber"):
        self.cx = Inches(w_in)
        self.cy = Inches(h_in)
        self.title = title
        self.author = author
        self.slides: List[Slide] = []

    def add_slide(self) -> Slide:
        s = Slide(self)
        self.slides.append(s)
        return s

    # convenient accessors for the report layer
    @property
    def W(self) -> int:
        return self.cx

    @property
    def H(self) -> int:
        return self.cy

    def save(self, path: str):
        z = zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED)

        # collect media (dedup by path) across slides
        media: List[str] = []
        media_index: Dict[str, int] = {}
        for s in self.slides:
            for p in s.images:
                if p not in media_index:
                    media_index[p] = len(media) + 1
                    media.append(p)

        # [Content_Types].xml
        slide_overrides = "".join(
            f'<Override PartName="/ppt/slides/slide{i+1}.xml" '
            f'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
            for i in range(len(self.slides)))
        z.writestr("[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="png" ContentType="image/png"/>'
            '<Default Extension="jpeg" ContentType="image/jpeg"/>'
            '<Default Extension="jpg" ContentType="image/jpeg"/>'
            '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
            '<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>'
            '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>'
            '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>'
            + slide_overrides +
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
            '</Types>')

        # _rels/.rels
        z.writestr("_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            '</Relationships>')

        # docProps
        z.writestr("docProps/core.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{_esc(self.title)}</dc:title><dc:creator>{_esc(self.author)}</dc:creator>'
            f'<cp:lastModifiedBy>{_esc(self.author)}</cp:lastModifiedBy></cp:coreProperties>')
        z.writestr("docProps/app.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
            'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
            f'<Application>PhalanxCyber SAP Scanner</Application><Slides>{len(self.slides)}</Slides>'
            '</Properties>')

        # ppt/presentation.xml
        sld_ids = "".join(
            f'<p:sldId id="{256 + i}" r:id="rId{i + 2}"/>' for i in range(len(self.slides)))
        z.writestr("ppt/presentation.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
            'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" saveSubsetFonts="1">'
            '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
            f'<p:sldIdLst>{sld_ids}</p:sldIdLst>'
            f'<p:sldSz cx="{self.cx}" cy="{self.cy}" type="screen16x9"/>'
            '<p:notesSz cx="6858000" cy="9144000"/></p:presentation>')

        # ppt/_rels/presentation.xml.rels
        pres_rels = ['<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>']
        for i in range(len(self.slides)):
            pres_rels.append(
                f'<Relationship Id="rId{i + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i + 1}.xml"/>')
        # theme relationship (after slides)
        theme_rid = "rId%d" % (len(self.slides) + 2)
        pres_rels.append(
            f'<Relationship Id="{theme_rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>')
        z.writestr("ppt/_rels/presentation.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + "".join(pres_rels) + '</Relationships>')

        # theme, master, layout
        z.writestr("ppt/theme/theme1.xml", _THEME_XML)
        z.writestr("ppt/slideMasters/slideMaster1.xml", _MASTER_XML)
        z.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>'
            '</Relationships>')
        z.writestr("ppt/slideLayouts/slideLayout1.xml", _LAYOUT_XML)
        z.writestr("ppt/slideLayouts/_rels/slideLayout1.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>'
            '</Relationships>')

        # media
        for idx, mpath in enumerate(media, 1):
            ext = "png" if mpath.lower().endswith("png") else "jpeg"
            with open(mpath, "rb") as fh:
                z.writestr(f"ppt/media/image{idx}.{ext}", fh.read())

        # slides + slide rels
        for i, s in enumerate(self.slides, 1):
            z.writestr(f"ppt/slides/slide{i}.xml", s._xml())
            rels = ['<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>']
            for j, p in enumerate(s.images, 1):
                mi = media_index[p]
                ext = "png" if p.lower().endswith("png") else "jpeg"
                rels.append(
                    f'<Relationship Id="rIdImg{j}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="../media/image{mi}.{ext}"/>')
            z.writestr(f"ppt/slides/_rels/slide{i}.xml.rels",
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                + "".join(rels) + '</Relationships>')

        z.close()


# ── static OOXML parts (valid minimal Office theme / master / blank layout) ──
_THEME_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Office">'
    '<a:themeElements>'
    '<a:clrScheme name="Office">'
    '<a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>'
    '<a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>'
    '<a:dk2><a:srgbClr val="1F2933"/></a:dk2><a:lt2><a:srgbClr val="EEECE1"/></a:lt2>'
    '<a:accent1><a:srgbClr val="0369A1"/></a:accent1><a:accent2><a:srgbClr val="DC2626"/></a:accent2>'
    '<a:accent3><a:srgbClr val="EA580C"/></a:accent3><a:accent4><a:srgbClr val="B45309"/></a:accent4>'
    '<a:accent5><a:srgbClr val="15803D"/></a:accent5><a:accent6><a:srgbClr val="4F46E5"/></a:accent6>'
    '<a:hlink><a:srgbClr val="0563C1"/></a:hlink><a:folHlink><a:srgbClr val="954F72"/></a:folHlink>'
    '</a:clrScheme>'
    '<a:fontScheme name="Office">'
    '<a:majorFont><a:latin typeface="Calibri Light"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>'
    '<a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont>'
    '</a:fontScheme>'
    '<a:fmtScheme name="Office">'
    '<a:fillStyleLst>'
    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
    '</a:fillStyleLst>'
    '<a:lnStyleLst>'
    '<a:ln w="6350" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln>'
    '<a:ln w="12700" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln>'
    '<a:ln w="19050" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln>'
    '</a:lnStyleLst>'
    '<a:effectStyleLst>'
    '<a:effectStyle><a:effectLst/></a:effectStyle>'
    '<a:effectStyle><a:effectLst/></a:effectStyle>'
    '<a:effectStyle><a:effectLst/></a:effectStyle>'
    '</a:effectStyleLst>'
    '<a:bgFillStyleLst>'
    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
    '</a:bgFillStyleLst>'
    '</a:fmtScheme>'
    '</a:themeElements></a:theme>')

_MASTER_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
    '<p:cSld><p:bg><p:bgRef idx="1001"><a:schemeClr val="bg1"/></p:bgRef></p:bg>'
    '<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
    '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
    '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld>'
    '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" '
    'accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>'
    '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
    '<p:txStyles>'
    '<p:titleStyle><a:lvl1pPr><a:defRPr sz="4400"><a:solidFill><a:schemeClr val="tx1"/></a:solidFill>'
    '<a:latin typeface="+mj-lt"/></a:defRPr></a:lvl1pPr></p:titleStyle>'
    '<p:bodyStyle><a:lvl1pPr><a:defRPr sz="1800"><a:solidFill><a:schemeClr val="tx1"/></a:solidFill>'
    '<a:latin typeface="+mn-lt"/></a:defRPr></a:lvl1pPr></p:bodyStyle>'
    '<p:otherStyle><a:defPPr><a:defRPr lang="en-US"/></a:defPPr></p:otherStyle>'
    '</p:txStyles></p:sldMaster>')

_LAYOUT_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank" preserve="1">'
    '<p:cSld name="Blank"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
    '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
    '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld>'
    '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>')
