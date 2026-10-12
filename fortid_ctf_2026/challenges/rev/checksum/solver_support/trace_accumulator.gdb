set pagination off
set confirm off
set debuginfod enabled off
python
import gdb
acc_events=[]
class AccTrace(gdb.Breakpoint):
    def __init__(self, spec, after, func, opaddr):
        self.after=after; self.func=func; self.opaddr=opaddr
        super().__init__(spec, internal=True)
    def stop(self):
        ptr=int(gdb.parse_and_eval('$rdi'))
        value=bytes(gdb.selected_inferior().read_memory(ptr,1))[0]
        acc_events.append((value, self.after, self.func, self.opaddr, ptr))
        return False
end
start < solver_support/in.flag
python
import gdb
main_static=0x6aa10
main_runtime=int(gdb.parse_and_eval('&main'))
load_bias=main_runtime-main_static
ops=[]
for line in open('solver_support/accumulator_ops.tsv'):
    after,funcaddr,name,mask,raw=line.rstrip('\n').split('\t',4)
    ops.append((int(after,16),name,int(funcaddr,16)))
for after,name,funcaddr in ops:
    AccTrace('*0x%x' % (load_bias+after), after, name, funcaddr)
print('LOAD_BIAS',hex(load_bias),'BREAKPOINTS',len(ops))
end
continue
python
from pathlib import Path
stream=bytes(row[0] for row in acc_events)
Path('solver_support/accumulator_stream.bin').write_bytes(stream)
Path('solver_support/accumulator_trace.tsv').write_text(''.join('%d\t%02x\t%x\t%s\t%x\t%x\n' % (i,v,pc,name,opaddr,ptr) for i,(v,pc,name,opaddr,ptr) in enumerate(acc_events)))
print('ACC_EVENT_COUNT',len(acc_events))
print('STREAM_HEX_PREFIX',stream[:64].hex())
print('FLAG_PREFIX_OFFSETS',[i for i in range(len(stream)) if stream.startswith(b'FortID{',i)])
print('PRINTABLE_RUNS_GE_6')
import re
for m in re.finditer(rb'[ -~]{6,}',stream):
    print(m.start(),m.group().decode('ascii'))
print('FINAL',stream[-1:].hex())
end
