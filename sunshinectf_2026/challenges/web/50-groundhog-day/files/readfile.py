import sys, gopher as g

def read(path):
    js = ('var x=new XMLHttpRequest();'
          'x.open("GET","file://' + path + '",false);'
          'x.send();'
          'document.write("<pre>S:"+x.status+":"+x.responseText+":E</pre>");')
    txt, info = g.pdf_text('<script>' + js + '</script>')
    return (txt or '').strip(), info

for p in sys.argv[1:]:
    t, info = read(p)
    print(f'--- {p}   [{info}]')
    print('   ', repr(t[:500]) if t else '(nothing rendered)')
