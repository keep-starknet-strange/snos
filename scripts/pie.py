from starkware.cairo.lang.vm.cairo_pie import CairoPie
import base64

with open("sexy_pie.txt", "rb") as f:
    cairo_pie = CairoPie.deserialize(base64.b64decode(f.read()))
    
cairo_pie.to_file("sexy.zip")
