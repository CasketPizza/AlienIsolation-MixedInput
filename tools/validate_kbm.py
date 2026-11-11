"""Offline validation only: never loads the ASI or launches the game.
Unicorn executes ONLY the mod's isolated hook against synthetic device structs.
"""
import hashlib, itertools, json, os, pathlib, re, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import *

DEV=pathlib.Path(__file__).resolve().parents[1]
ROOT=pathlib.Path(os.environ.get('ALIEN_ISOLATION_DIR', DEV.parent)).resolve()
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def protected():
    expected='dde66521798aae8c39ed4e7a3400f561fcecfff83619d1426b9e0cedf5819a90'
    game=ROOT/'AI.exe'
    assert game.is_file(), f'AI.exe not found in {ROOT}'
    assert sha(game)==expected, 'Unsupported AI.exe SHA-256'
    return {'AI.exe':expected}

def validate():
    originals=protected()
    game=pefile.PE(str(ROOT/'AI.exe'))
    artifact=DEV/'build/kbm-prompts/AlienIsolation.MixedInput.asi'
    plugin=pefile.PE(str(artifact))
    assert game.FILE_HEADER.Machine==plugin.FILE_HEADER.Machine==0x14c
    assert plugin.FILE_HEADER.Characteristics & 0x2000
    assert b'InitializeASI' in [x.name for x in plugin.DIRECTORY_ENTRY_EXPORT.symbols]
    imports=[x.dll.decode() for x in plugin.DIRECTORY_ENTRY_IMPORT]
    assert set(x.lower() for x in imports)<={'kernel32.dll','advapi32.dll'}
    src=(DEV/'src/MixedInputKBMPrompts.cpp').read_text()
    raw=re.search(r'const BYTE context\[\]=\{(.*?)\};',src,re.S)[1]
    context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE desktopContext\[\]=\{(.*?)\};',src,re.S)[1]
    desktop_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE controllerContext\[\]=\{(.*?)\};',src,re.S)[1]
    controller_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE routeContext\[\]=\{(.*?)\};',src,re.S)[1]
    route_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE axisContext\[\]=\{(.*?)\};',src,re.S)[1]
    axis_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE promptContext\[\]=\{(.*?)\};',src,re.S)[1]
    prompt_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE promptModeContext\[\]=\{(.*?)\};',src,re.S)[1]
    prompt_mode_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE rawMouseContext\[\]=\{(.*?)\};',src,re.S)[1]
    raw_mouse_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE mouseActivityContext\[\]=\{(.*?)\};',src,re.S)[1]
    mouse_activity_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE keyboardActivityContext\[\]=\{(.*?)\};',src,re.S)[1]
    keyboard_activity_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    raw=re.search(r'const BYTE controllerUpdateContext\[\]=\{(.*?)\};',src,re.S)[1]
    controller_update_context=bytes(int(s,16) for s in re.findall(r'0x([0-9a-fA-F]+)',raw))
    text=game.sections[0]
    assert text.get_data().count(context)==1
    assert text.VirtualAddress+text.get_data().index(context)==0x57cc10
    assert text.get_data().count(desktop_context)==1
    assert text.VirtualAddress+text.get_data().index(desktop_context)==0x57cd4f
    assert text.get_data().count(controller_context)==1
    assert text.VirtualAddress+text.get_data().index(controller_context)==0x57cd89
    assert text.get_data().count(route_context)==1
    assert text.VirtualAddress+text.get_data().index(route_context)==0x57cdc0
    assert text.get_data().count(axis_context)==1
    assert text.VirtualAddress+text.get_data().index(axis_context)==0x57d6c0
    assert text.get_data().count(prompt_context)==1
    assert text.VirtualAddress+text.get_data().index(prompt_context)==0x57d454
    assert text.get_data().count(prompt_mode_context)==1
    assert text.VirtualAddress+text.get_data().index(prompt_mode_context)==0x42d044
    assert text.get_data().count(raw_mouse_context)==1
    assert text.VirtualAddress+text.get_data().index(raw_mouse_context)==0x60e99c
    assert text.get_data().count(mouse_activity_context)==1
    assert text.VirtualAddress+text.get_data().index(mouse_activity_context)==0x9bbe70
    assert text.get_data().count(keyboard_activity_context)==1
    assert text.VirtualAddress+text.get_data().index(keyboard_activity_context)==0x60ee00
    assert text.get_data().count(controller_update_context)==1
    assert text.VirtualAddress+text.get_data().index(controller_update_context)==0x60f264
    assert game.get_data(0x57cc6d,6)==bytes.fromhex('89 be 7c 4a 00 00')
    assert game.get_data(0x57cd44,11)==bytes.fromhex('80 b8 89 02 00 00 00 75 02 b3 01')
    assert game.get_data(0x590a36,5)==bytes.fromhex('e9 85 c1 fe ff')
    assert game.get_data(0x60e9f0,7)==bytes.fromhex('c7 43 0c 01 00 00 00')
    assert game.get_data(0x60e566,7)==bytes.fromhex('c7 46 0c 02 00 00 00')
    for table in (0x13e75e0,0x13e7628):
        for slot in (0x28,0x40):
            assert struct.unpack('<I',game.get_data(table-0x400000+slot,4))[0]==0xa69c90
    assert game.get_data(0x669c90,1)==b'\xc3'
    skip_pattern=bytes.fromhex('74 10 53 53 6a 1b')
    assert text.get_data().count(skip_pattern)==1
    skip_rva=text.VirtualAddress+text.get_data().index(skip_pattern)
    assert abs(skip_rva-0x57cc16)>0x100
    md=Cs(CS_ARCH_X86,CS_MODE_32)
    displaced=list(md.disasm(context[6:14],0x97cc16))
    assert [(i.mnemonic,i.size) for i in displaced]==[('cmp',4),('mov',4)]
    desktop_displaced=list(md.disasm(desktop_context[11:21],0x97cd5a))
    assert [(i.mnemonic,i.size) for i in desktop_displaced]==[('mov',6),('cmp',4)]
    controller_displaced=list(md.disasm(controller_context[16:24],0x97cd99))
    assert [(i.mnemonic,i.size) for i in controller_displaced]==[('cmp',4),('mov',4)]
    route_displaced=list(md.disasm(route_context[5:15],0x97cdc5))
    assert [(i.mnemonic,i.size) for i in route_displaced]==[('mov',6),('test',2),('je',2)]
    axis_displaced=list(md.disasm(axis_context[20:26],0x97d6d4))
    assert [(i.mnemonic,i.size) for i in axis_displaced]==[('cmp',4),('je',2)]
    prompt_displaced=list(md.disasm(prompt_context[34:40],0x97d476))
    assert [(i.mnemonic,i.size) for i in prompt_displaced]==[('cmp',4),('jne',2)]
    prompt_mode_displaced=list(md.disasm(prompt_mode_context[10:22],0x82d04e))
    assert [(i.mnemonic,i.size) for i in prompt_mode_displaced]==[('cmp',4),('mov',8)]
    raw_mouse_displaced=list(md.disasm(raw_mouse_context[:6],0xa0e99c))
    assert [(i.mnemonic,i.size) for i in raw_mouse_displaced]==[('test',4),('jne',2)]
    mouse_activity_displaced=list(md.disasm(mouse_activity_context,0xdbbe70))
    assert [(i.mnemonic,i.size) for i in mouse_activity_displaced]==[('xor',2),('cmp',3),('setne',3),('ret',1)]
    keyboard_activity_displaced=list(md.disasm(keyboard_activity_context,0xa0ee00))
    assert [(i.mnemonic,i.size) for i in keyboard_activity_displaced]==[('mov',6),('ret',1)]
    controller_update_displaced=list(md.disasm(controller_update_context[:9],0xa0f264))
    assert [(i.mnemonic,i.size) for i in controller_update_displaced]==[('pop',1),('movss',8)]
    assert context[47:]==bytes.fromhex('43 3b 5c 24 14 72 ca')
    # Extract the actual linked hook, not a second hand-written implementation.
    code=plugin.sections[0].get_data()
    prefix=bytes.fromhex('83 7d 0c 01 74 14 83 7d 0c 02')
    assert code.count(prefix)==1
    hook_rva=plugin.sections[0].VirtualAddress+code.index(prefix)
    desktop_prefix=bytes.fromhex('8b 96 7c 4a 00 00 85 d2')
    assert code.count(desktop_prefix)==1
    desktop_hook_rva=plugin.sections[0].VirtualAddress+code.index(desktop_prefix)
    controller_prefix=bytes.fromhex('83 7f 0c 00 75')
    assert code.count(controller_prefix)==1
    controller_hook_rva=plugin.sections[0].VirtualAddress+code.index(controller_prefix)
    route_prefix=bytes.fromhex('8b 86 7c 4a 00 00 85 c0')
    assert code.count(route_prefix)==1
    route_hook_rva=plugin.sections[0].VirtualAddress+code.index(route_prefix)
    axis_prefix=bytes.fromhex('80 7e 11 00 74')
    assert code.count(axis_prefix)==1
    axis_hook_rva=plugin.sections[0].VirtualAddress+code.index(axis_prefix)
    prompt_prefix=bytes.fromhex('83 7a 0c 00')
    assert code.count(prompt_prefix)==1
    prompt_hook_rva=plugin.sections[0].VirtualAddress+code.index(prompt_prefix)
    prompt_mode_matches=list(re.finditer(rb'\x52\x83\x3d....\x01\x75.\x8b\x97\x3c\x10\x00\x00',code,re.S))
    assert len(prompt_mode_matches)==1
    prompt_mode_hook_rva=plugin.sections[0].VirtualAddress+prompt_mode_matches[0].start()
    raw_mouse_prefix=bytes.fromhex('f6 47 10 01 75')
    assert code.count(raw_mouse_prefix)==1
    raw_mouse_hook_rva=plugin.sections[0].VirtualAddress+code.index(raw_mouse_prefix)
    mouse_activity_prefix=bytes.fromhex('33 c0 8b 51 54 3b d0 74')
    assert code.count(mouse_activity_prefix)==1
    mouse_activity_hook_rva=plugin.sections[0].VirtualAddress+code.index(mouse_activity_prefix)
    keyboard_activity_prefix=bytes.fromhex('80 b9 24 02 00 00 00')
    assert code.count(keyboard_activity_prefix)==1
    keyboard_activity_hook_rva=plugin.sections[0].VirtualAddress+code.index(keyboard_activity_prefix)
    controller_update_prefix=bytes.fromhex('5f f3 0f 11 8e 7c 02 00 00 9c 60 56 e8')
    assert code.count(controller_update_prefix)==1
    controller_update_hook_rva=plugin.sections[0].VirtualAddress+code.index(controller_update_prefix)
    tests=0
    for base in (0x10000000,0x50000000):
        p=pefile.PE(str(artifact)); p.relocate_image(base)
        image=p.get_memory_mapped_image()
        ins=list(md.disasm(image[hook_rva:hook_rva+43],base+hook_rva))
        jumps=[i for i in ins if i.mnemonic=='jmp']
        assert len(jumps)==2
        slots=[struct.unpack('<I',i.bytes[2:6])[0] for i in jumps]
        inc=next(i for i in ins if i.mnemonic=='lock inc')
        counter=struct.unpack('<I',inc.bytes[3:7])[0]
        for device_type in range(6):
            for enabled in (0,1):
                for selected in (0,1):
                    u=Uc(UC_ARCH_X86,UC_MODE_32)
                    u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
                    u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
                    dev=0x20001000; stack=0x20008000
                    data=bytearray([0xa5]*0x300)
                    struct.pack_into('<I',data,12,device_type)
                    data[16]=enabled; data[17]=selected
                    u.mem_write(dev,bytes(data))
                    u.mem_write(slots[0],struct.pack('<I',0x30000000))
                    u.mem_write(slots[1],struct.pack('<I',0x30000010))
                    u.mem_write(counter,struct.pack('<I',0))
                    regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                          UC_X86_REG_ECX:0x33445566,UC_X86_REG_EDX:0x44556677,
                          UC_X86_REG_ESI:0x55667788,UC_X86_REG_EDI:0x66778899,
                          UC_X86_REG_EBP:dev,UC_X86_REG_ESP:stack}
                    for reg,value in regs.items(): u.reg_write(reg,value)
                    u.reg_write(UC_X86_REG_EFLAGS,0x202)
                    stops=[]
                    def stop(uc,address,size,user):
                        if address in (0x30000000,0x30000010):
                            stops.append(address); uc.emu_stop()
                    u.hook_add(UC_HOOK_CODE,stop)
                    u.emu_start(base+hook_rva,0,count=40)
                    keep=device_type in (1,2)
                    assert stops==[0x30000010 if keep else 0x30000000]
                    data[17]=1 if keep else 0
                    assert u.mem_read(dev,len(data))==data
                    assert all(u.reg_read(r)==v for r,v in regs.items())
                    assert struct.unpack('<I',u.mem_read(counter,4))[0]==int(keep)
                    if not keep:
                        flags=u.reg_read(UC_X86_REG_EFLAGS)
                        assert flags&0x8d5==(0x44 if selected==0 else 0) # all CMP status flags
                    tests+=1
        desktop_ins=list(md.disasm(image[desktop_hook_rva:desktop_hook_rva+61],base+desktop_hook_rva))
        desktop_jumps=[i for i in desktop_ins if i.bytes.startswith(b'\xff\x25')]
        desktop_incs=[i for i in desktop_ins if i.mnemonic=='lock inc']
        assert len(desktop_jumps)==2 and len(desktop_incs)==1
        desktop_slots=[struct.unpack('<I',i.bytes[2:6])[0] for i in desktop_jumps]
        desktop_counters=[struct.unpack('<I',i.bytes[3:7])[0] for i in desktop_incs]
        for controller_state in ('none','connected','disconnected'):
            for keyboard_selected in (0,1):
                u=Uc(UC_ARCH_X86,UC_MODE_32)
                u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
                u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
                manager=0x20000000; controller=0x20006000; keyboard=0x20007000; stack=0x20008000
                manager_data=bytearray([0xa5]*0x5000)
                struct.pack_into('<I',manager_data,0x4a74,keyboard)
                struct.pack_into('<I',manager_data,0x4a7c,0 if controller_state=='none' else controller)
                u.mem_write(manager,bytes(manager_data))
                controller_data=bytearray([0x5a]*0x300)
                controller_data[0x289]=int(controller_state=='connected')
                keyboard_data=bytearray([0x3c]*0x300); keyboard_data[0x11]=keyboard_selected
                u.mem_write(controller,bytes(controller_data)); u.mem_write(keyboard,bytes(keyboard_data))
                for index,slot in enumerate(desktop_slots):
                    u.mem_write(slot,struct.pack('<I',0x30000000+index*0x10))
                for counter_address in desktop_counters: u.mem_write(counter_address,struct.pack('<I',0))
                regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                      UC_X86_REG_ECX:0x33445566,UC_X86_REG_EDX:0x44556677,
                      UC_X86_REG_ESI:manager,UC_X86_REG_EDI:0x66778899,
                      UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
                for reg,value in regs.items(): u.reg_write(reg,value)
                u.reg_write(UC_X86_REG_EFLAGS,0x202)
                stops=[]
                def desktop_stop(uc,address,size,user):
                    if 0x30000000<=address<=0x30000020:
                        stops.append(address); uc.emu_stop()
                u.hook_add(UC_HOOK_CODE,desktop_stop)
                u.emu_start(base+desktop_hook_rva,0,count=40)
                expected_index=1 if controller_state=='none' else 0
                assert stops==[0x30000000+expected_index*0x10]
                assert u.mem_read(manager,len(manager_data))==manager_data
                assert u.mem_read(controller,len(controller_data))==controller_data
                assert u.mem_read(keyboard,len(keyboard_data))==keyboard_data
                assert all(u.reg_read(r)==v for r,v in regs.items() if r!=UC_X86_REG_EDX)
                expected_edx=keyboard if controller_state=='none' else controller
                assert u.reg_read(UC_X86_REG_EDX)==expected_edx
                counts=[struct.unpack('<I',u.mem_read(address,4))[0] for address in desktop_counters]
                assert counts==[int(controller_state=='disconnected')]
                if controller_state=='none':
                    flags=u.reg_read(UC_X86_REG_EFLAGS)
                    assert flags&0x8d5==(0x44 if keyboard_selected==0 else 0)
                tests+=1
        controller_ins=list(md.disasm(image[controller_hook_rva:controller_hook_rva+46],base+controller_hook_rva))
        controller_jumps=[i for i in controller_ins if i.bytes.startswith(b'\xff\x25')]
        controller_incs=[i for i in controller_ins if i.mnemonic=='lock inc']
        assert len(controller_jumps)==2 and len(controller_incs)==1
        controller_slots=[struct.unpack('<I',i.bytes[2:6])[0] for i in controller_jumps]
        controller_counter=struct.unpack('<I',controller_incs[0].bytes[3:7])[0]
        for device_type in range(4):
            for connected in (0,1):
                for selected in (0,1):
                    u=Uc(UC_ARCH_X86,UC_MODE_32)
                    u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
                    u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
                    dev=0x20001000; stack=0x20008000
                    data=bytearray([0x69]*0x300)
                    struct.pack_into('<I',data,12,device_type); data[17]=selected; data[0x289]=connected
                    u.mem_write(dev,bytes(data))
                    for index,slot in enumerate(controller_slots):
                        u.mem_write(slot,struct.pack('<I',0x30000000+index*0x10))
                    u.mem_write(controller_counter,struct.pack('<I',0))
                    regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                          UC_X86_REG_ECX:0x33445566,UC_X86_REG_EDX:0x44556677,
                          UC_X86_REG_ESI:0x55667788,UC_X86_REG_EDI:dev,
                          UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
                    for reg,value in regs.items(): u.reg_write(reg,value)
                    stops=[]
                    def controller_stop(uc,address,size,user):
                        if 0x30000000<=address<=0x30000010:
                            stops.append(address); uc.emu_stop()
                    u.hook_add(UC_HOOK_CODE,controller_stop)
                    u.emu_start(base+controller_hook_rva,0,count=40)
                    keep=device_type==0 and connected==1
                    assert stops==[0x30000000 if keep else 0x30000010]
                    data[17]=1 if keep else 0
                    assert u.mem_read(dev,len(data))==data
                    assert all(u.reg_read(r)==v for r,v in regs.items())
                    assert struct.unpack('<I',u.mem_read(controller_counter,4))[0]==int(keep)
                    if not keep:
                        flags=u.reg_read(UC_X86_REG_EFLAGS)
                        assert flags&0x8d5==(0x44 if selected==0 else 0)
                    tests+=1
        route_ins=list(md.disasm(image[route_hook_rva:route_hook_rva+54],base+route_hook_rva))
        route_jumps=[i for i in route_ins if i.bytes.startswith(b'\xff\x25')]
        route_incs=[i for i in route_ins if i.mnemonic=='lock inc']
        assert len(route_jumps)==3 and len(route_incs)==1
        route_slots=[struct.unpack('<I',i.bytes[2:6])[0] for i in route_jumps]
        assert route_slots[0]==route_slots[2]
        route_counter=struct.unpack('<I',route_incs[0].bytes[3:7])[0]
        for controller_state in ('none','connected','disconnected'):
            for has_route in (0,1):
                u=Uc(UC_ARCH_X86,UC_MODE_32)
                u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
                u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
                manager=0x20000000; controller=0x20006000; route=0x20007000; stack=0x20008000
                manager_data=bytearray([0x96]*0x5000)
                struct.pack_into('<I',manager_data,0x4a7c,0 if controller_state=='none' else controller)
                struct.pack_into('<I',manager_data,0x4a80,route if has_route else 0)
                controller_data=bytearray([0x78]*0x300); controller_data[0x289]=int(controller_state=='connected')
                route_data=bytearray([0x87]*0x100)
                u.mem_write(manager,bytes(manager_data)); u.mem_write(controller,bytes(controller_data)); u.mem_write(route,bytes(route_data))
                u.mem_write(route_slots[0],struct.pack('<I',0x30000000))
                u.mem_write(route_slots[1],struct.pack('<I',0x30000010))
                u.mem_write(route_counter,struct.pack('<I',0))
                regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                      UC_X86_REG_ECX:0x33445566,UC_X86_REG_EDX:0x44556677,
                      UC_X86_REG_ESI:manager,UC_X86_REG_EDI:0x66778899,
                      UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
                for reg,value in regs.items(): u.reg_write(reg,value)
                stops=[]
                def route_stop(uc,address,size,user):
                    if 0x30000000<=address<=0x30000010:
                        stops.append(address); uc.emu_stop()
                u.hook_add(UC_HOOK_CODE,route_stop)
                u.emu_start(base+route_hook_rva,0,count=40)
                skip=controller_state=='connected' or not has_route
                assert stops==[0x30000000 if skip else 0x30000010]
                assert u.mem_read(manager,len(manager_data))==manager_data
                assert u.mem_read(controller,len(controller_data))==controller_data
                assert u.mem_read(route,len(route_data))==route_data
                assert all(u.reg_read(r)==v for r,v in regs.items() if r not in (UC_X86_REG_EAX,UC_X86_REG_ECX))
                expected_eax=0 if controller_state=='none' else controller
                assert u.reg_read(UC_X86_REG_EAX)==expected_eax
                if controller_state!='connected': assert u.reg_read(UC_X86_REG_ECX)==(route if has_route else 0)
                assert struct.unpack('<I',u.mem_read(route_counter,4))[0]==int(controller_state=='connected')
                tests+=1
        axis_ins=list(md.disasm(image[axis_hook_rva:axis_hook_rva+50],base+axis_hook_rva))
        axis_jumps=[i for i in axis_ins if i.bytes.startswith(b'\xff\x25')]
        axis_incs=[i for i in axis_ins if i.mnemonic=='lock inc']
        assert len(axis_jumps)==2 and len(axis_incs)==1
        axis_slots=[struct.unpack('<I',i.bytes[2:6])[0] for i in axis_jumps]
        axis_counter=struct.unpack('<I',axis_incs[0].bytes[3:7])[0]
        for controller_state in ('none','connected','disconnected'):
            for controller_selected in (0,1):
                for keyboard_selected in (0,1):
                    u=Uc(UC_ARCH_X86,UC_MODE_32)
                    u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
                    u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
                    context=0x20000000; keyboard=0x20003000; controller=0x20004000; stack=0x20008000
                    context_data=bytearray([0x35]*0x2000)
                    struct.pack_into('<I',context_data,0x103c,0 if controller_state=='none' else controller)
                    keyboard_data=bytearray([0x53]*0x300); keyboard_data[0x11]=keyboard_selected
                    controller_data=bytearray([0x71]*0x300)
                    controller_data[0x11]=controller_selected
                    controller_data[0x289]=int(controller_state=='connected')
                    u.mem_write(context,bytes(context_data)); u.mem_write(keyboard,bytes(keyboard_data)); u.mem_write(controller,bytes(controller_data))
                    for index,slot in enumerate(axis_slots):
                        u.mem_write(slot,struct.pack('<I',0x30000000+index*0x10))
                    u.mem_write(axis_counter,struct.pack('<I',0))
                    regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                          UC_X86_REG_ECX:context,UC_X86_REG_EDX:0x44556677,
                          UC_X86_REG_ESI:keyboard,UC_X86_REG_EDI:0x66778899,
                          UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
                    for reg,value in regs.items(): u.reg_write(reg,value)
                    stops=[]
                    def axis_stop(uc,address,size,user):
                        if 0x30000000<=address<=0x30000010:
                            stops.append(address); uc.emu_stop()
                    u.hook_add(UC_HOOK_CODE,axis_stop)
                    u.emu_start(base+axis_hook_rva,0,count=40)
                    preserve=keyboard_selected and controller_state=='connected' and controller_selected
                    skip=not keyboard_selected or preserve
                    assert stops==[0x30000000 if skip else 0x30000010]
                    assert u.mem_read(context,len(context_data))==context_data
                    assert u.mem_read(keyboard,len(keyboard_data))==keyboard_data
                    assert u.mem_read(controller,len(controller_data))==controller_data
                    assert all(u.reg_read(r)==v for r,v in regs.items() if r!=UC_X86_REG_EAX)
                    assert struct.unpack('<I',u.mem_read(axis_counter,4))[0]==int(preserve)
                    tests+=1
        prompt_ins=list(md.disasm(image[prompt_hook_rva:prompt_hook_rva+200],base+prompt_hook_rva))
        prompt_jumps=[i for i in prompt_ins if i.bytes.startswith(b'\xff\x25')]
        prompt_incs=[i for i in prompt_ins if i.mnemonic=='lock inc']
        assert len(prompt_jumps)==4 and len(prompt_incs)==2
        prompt_slots=[struct.unpack('<I',i.bytes[2:6])[0] for i in prompt_jumps]
        next_slot=max(set(prompt_slots),key=prompt_slots.count)
        found_slot=next(slot for slot in set(prompt_slots) if slot!=next_slot)
        assert prompt_slots.count(next_slot)==3 and prompt_slots.count(found_slot)==1
        prompt_counters=[struct.unpack('<I',i.bytes[3:7])[0] for i in prompt_incs]
        prompt_gate=next(i for i in prompt_ins if i.bytes.startswith(b'\x83\x3d') and i.bytes[-1:]==b'\x01')
        last_prompt_address=struct.unpack('<I',prompt_gate.bytes[2:6])[0]
        assert struct.unpack('<I',image[last_prompt_address-base:last_prompt_address-base+4])[0]==0
        for controller_state in ('none','connected','disconnected'):
            for controller_selected in (0,1):
                for current_type in range(3):
                    for current_selected in (0,1):
                        for later_controller,last_device in itertools.product((0,1),(0,1)):
                            u=Uc(UC_ARCH_X86,UC_MODE_32)
                            u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
                            u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
                            context=0x20000000; current=0x20003000; controller=0x20004000
                            bindings=0x20005000; keyboard=0x20006000; stack=0x20008000
                            context_data=bytearray([0x36]*0x2000)
                            struct.pack_into('<I',context_data,0x103c,0 if controller_state=='none' else controller)
                            struct.pack_into('<I',context_data,0x1040,keyboard)
                            current_data=bytearray([0x54]*0x300)
                            struct.pack_into('<I',current_data,0xc,current_type); current_data[0x11]=current_selected
                            controller_data=bytearray([0x72]*0x300)
                            struct.pack_into('<I',controller_data,0xc,0); controller_data[0x11]=controller_selected
                            controller_data[0x289]=int(controller_state=='connected')
                            keyboard_data=bytearray([0x42]*0x300); keyboard_data[0x11]=1
                            binding_data=bytearray([0x63]*0x20)
                            struct.pack_into('<H',binding_data,4,1); binding_data[6]=current_type
                            struct.pack_into('<H',binding_data,12,2); binding_data[14]=0 if later_controller else 1
                            u.mem_write(context,bytes(context_data)); u.mem_write(current,bytes(current_data))
                            u.mem_write(controller,bytes(controller_data)); u.mem_write(keyboard,bytes(keyboard_data))
                            u.mem_write(bindings,bytes(binding_data))
                            u.mem_write(next_slot,struct.pack('<I',0x30000000))
                            u.mem_write(found_slot,struct.pack('<I',0x30000010))
                            for address in prompt_counters: u.mem_write(address,struct.pack('<I',0))
                            u.mem_write(last_prompt_address,struct.pack('<I',last_device))
                            regs={UC_X86_REG_EAX:bindings,UC_X86_REG_EBX:0x22334455,
                                  UC_X86_REG_ECX:context,UC_X86_REG_EDX:current,
                                  UC_X86_REG_ESI:0,UC_X86_REG_EDI:2,
                                  UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
                            for reg,value in regs.items(): u.reg_write(reg,value)
                            stops=[]
                            def prompt_stop(uc,address,size,user):
                                if 0x30000000<=address<=0x30000010:
                                    stops.append(address); uc.emu_stop()
                            u.hook_add(UC_HOOK_CODE,prompt_stop)
                            u.emu_start(base+prompt_hook_rva,0,count=80)
                            prefer_controller=(last_device==1 and current_type!=0 and controller_state=='connected' and
                                               controller_selected and later_controller)
                            prefer_desktop=(last_device==0 and current_type==0 and not later_controller)
                            prefer=prefer_controller or prefer_desktop
                            next_binding=prefer or not current_selected
                            assert stops==[0x30000000 if next_binding else 0x30000010]
                            assert u.mem_read(context,len(context_data))==context_data
                            assert u.mem_read(current,len(current_data))==current_data
                            assert u.mem_read(controller,len(controller_data))==controller_data
                            assert u.mem_read(keyboard,len(keyboard_data))==keyboard_data
                            assert u.mem_read(bindings,len(binding_data))==binding_data
                            assert all(u.reg_read(r)==v for r,v in regs.items())
                            counts=[struct.unpack('<I',u.mem_read(a,4))[0] for a in prompt_counters]
                            assert counts==[int(prefer_controller),int(prefer_desktop)]
                            tests+=1
        prompt_mode_ins=list(md.disasm(image[prompt_mode_hook_rva:prompt_mode_hook_rva+80],base+prompt_mode_hook_rva))
        prompt_mode_jumps=[i for i in prompt_mode_ins if i.bytes.startswith(b'\xff\x25')]
        prompt_mode_incs=[i for i in prompt_mode_ins if i.mnemonic=='lock inc']
        assert len(prompt_mode_jumps)==2 and len(prompt_mode_incs)==1
        prompt_mode_slots=[struct.unpack('<I',i.bytes[2:6])[0] for i in prompt_mode_jumps]
        prompt_mode_counter=struct.unpack('<I',prompt_mode_incs[0].bytes[3:7])[0]
        assert struct.unpack('<I',image[prompt_mode_hook_rva+3:prompt_mode_hook_rva+7])[0]==last_prompt_address
        for controller_state in ('none','connected','disconnected'):
            for controller_selected in (0,1):
                for keyboard_selected,last_device in itertools.product((0,1),(0,1)):
                    u=Uc(UC_ARCH_X86,UC_MODE_32)
                    u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
                    u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
                    context=0x20000000; keyboard=0x20003000; controller=0x20004000; stack=0x20008000
                    context_data=bytearray([0x37]*0x2000)
                    struct.pack_into('<I',context_data,0x103c,0 if controller_state=='none' else controller)
                    keyboard_data=bytearray([0x55]*0x300); keyboard_data[0x11]=keyboard_selected
                    controller_data=bytearray([0x73]*0x300); controller_data[0x11]=controller_selected
                    controller_data[0x289]=int(controller_state=='connected')
                    stack_data=bytearray([0x91]*0x1000)
                    u.mem_write(context,bytes(context_data)); u.mem_write(keyboard,bytes(keyboard_data))
                    u.mem_write(controller,bytes(controller_data)); u.mem_write(stack,bytes(stack_data))
                    for index,slot in enumerate(prompt_mode_slots):
                        u.mem_write(slot,struct.pack('<I',0x30000000+index*0x10))
                    u.mem_write(prompt_mode_counter,struct.pack('<I',0))
                    u.mem_write(last_prompt_address,struct.pack('<I',last_device))
                    regs={UC_X86_REG_EAX:keyboard,UC_X86_REG_EBX:0x22334455,
                          UC_X86_REG_ECX:0x33445566,UC_X86_REG_EDX:0x44556677,
                          UC_X86_REG_ESI:0x55667788,UC_X86_REG_EDI:context,
                          UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
                    for reg,value in regs.items(): u.reg_write(reg,value)
                    stops=[]
                    def prompt_mode_stop(uc,address,size,user):
                        if 0x30000000<=address<=0x30000010:
                            stops.append(address); uc.emu_stop()
                    u.hook_add(UC_HOOK_CODE,prompt_mode_stop)
                    u.emu_start(base+prompt_mode_hook_rva,0,count=60)
                    force=last_device==1 and controller_state=='connected' and controller_selected
                    assert stops==[0x30000000 if force else 0x30000010]
                    stack_data[0xbf]=0 if force else 1
                    assert u.mem_read(context,len(context_data))==context_data
                    assert u.mem_read(keyboard,len(keyboard_data))==keyboard_data
                    assert u.mem_read(controller,len(controller_data))==controller_data
                    assert u.mem_read(stack,len(stack_data))==stack_data
                    assert all(u.reg_read(r)==v for r,v in regs.items())
                    assert struct.unpack('<I',u.mem_read(prompt_mode_counter,4))[0]==int(force)
                    if not force:
                        flags=u.reg_read(UC_X86_REG_EFLAGS)
                        assert flags&0x8d5==(0x44 if keyboard_selected==0 else 0)
                    tests+=1
        raw_ins=list(md.disasm(image[raw_mouse_hook_rva:raw_mouse_hook_rva+104],base+raw_mouse_hook_rva))
        raw_jumps=[i for i in raw_ins if i.bytes.startswith(b'\xff\x25')]
        raw_incs=[i for i in raw_ins if i.mnemonic=='lock inc']
        raw_movs=[i for i in raw_ins if i.bytes.startswith(b'\xc7\x05')]
        assert len(raw_jumps)==2 and len(raw_incs)==2 and len(raw_movs)==2
        raw_slots=[struct.unpack('<I',i.bytes[2:6])[0] for i in raw_jumps]
        raw_counters=[struct.unpack('<I',i.bytes[3:7])[0] for i in raw_incs]
        motion_pending=struct.unpack('<I',raw_movs[0].bytes[2:6])[0]
        assert struct.unpack('<I',raw_movs[1].bytes[2:6])[0]==last_prompt_address
        for absolute,(dx,dy),last_device in itertools.product((0,1),((0,0),(1,0),(0,-2)),(0,1)):
            u=Uc(UC_ARCH_X86,UC_MODE_32)
            u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
            u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
            packet=0x20001000; stack=0x20008000
            packet_data=bytearray([0x62]*0x100)
            struct.pack_into('<I',packet_data,0x10,absolute)
            struct.pack_into('<i',packet_data,0x1c,dx); struct.pack_into('<i',packet_data,0x20,dy)
            u.mem_write(packet,bytes(packet_data))
            for index,slot in enumerate(raw_slots): u.mem_write(slot,struct.pack('<I',0x30000000+index*0x10))
            for address in raw_counters: u.mem_write(address,struct.pack('<I',0))
            u.mem_write(motion_pending,struct.pack('<I',0)); u.mem_write(last_prompt_address,struct.pack('<I',last_device))
            regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                  UC_X86_REG_ECX:0x33445566,UC_X86_REG_EDX:0x44556677,
                  UC_X86_REG_ESI:0x55667788,UC_X86_REG_EDI:packet,
                  UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
            for reg,value in regs.items(): u.reg_write(reg,value)
            stops=[]
            def raw_stop(uc,address,size,user):
                if 0x30000000<=address<=0x30000010: stops.append(address); uc.emu_stop()
            u.hook_add(UC_HOOK_CODE,raw_stop); u.emu_start(base+raw_mouse_hook_rva,0,count=80)
            moved=not absolute and (dx!=0 or dy!=0)
            assert stops==[0x30000010 if absolute else 0x30000000]
            assert u.mem_read(packet,len(packet_data))==packet_data
            assert all(u.reg_read(r)==v for r,v in regs.items())
            assert struct.unpack('<I',u.mem_read(motion_pending,4))[0]==int(moved)
            assert [struct.unpack('<I',u.mem_read(a,4))[0] for a in raw_counters]==[int(moved),int(moved and last_device==1)]
            assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==(0 if moved else last_device)
            tests+=1
        mouse_ins=list(md.disasm(image[mouse_activity_hook_rva:mouse_activity_hook_rva+80],base+mouse_activity_hook_rva))
        mouse_cmps=[i for i in mouse_ins if i.bytes.startswith(b'\x83\x3d')]
        mouse_movs=[i for i in mouse_ins if i.bytes.startswith(b'\xc7\x05')]
        mouse_xchgs=[i for i in mouse_ins if i.bytes.startswith(b'\x87\x05')]
        mouse_incs=[i for i in mouse_ins if i.mnemonic=='lock inc']
        assert len(mouse_cmps)==len(mouse_xchgs)==len(mouse_incs)==1 and len(mouse_movs)==2
        assert struct.unpack('<I',mouse_cmps[0].bytes[2:6])[0]==last_prompt_address
        assert struct.unpack('<I',mouse_movs[0].bytes[2:6])[0]==motion_pending
        assert struct.unpack('<I',mouse_movs[1].bytes[2:6])[0]==last_prompt_address
        assert struct.unpack('<I',mouse_xchgs[0].bytes[2:6])[0]==motion_pending
        desktop_counter=struct.unpack('<I',mouse_incs[0].bytes[3:7])[0]
        for buttons,pending,last_device in itertools.product((0,1,3),(0,1),(0,1)):
            u=Uc(UC_ARCH_X86,UC_MODE_32)
            u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
            u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
            mouse=0x20001000; stack=0x20008000
            mouse_data=bytearray([0x64]*0x300); struct.pack_into('<I',mouse_data,0x54,buttons)
            u.mem_write(mouse,bytes(mouse_data)); u.mem_write(stack,struct.pack('<I',0x30000000))
            u.mem_write(motion_pending,struct.pack('<I',pending)); u.mem_write(last_prompt_address,struct.pack('<I',last_device))
            u.mem_write(desktop_counter,struct.pack('<I',0))
            regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                  UC_X86_REG_ECX:mouse,UC_X86_REG_EDX:0x44556677,
                  UC_X86_REG_ESI:0x55667788,UC_X86_REG_EDI:0x66778899,
                  UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
            for reg,value in regs.items(): u.reg_write(reg,value)
            stops=[]
            def return_stop(uc,address,size,user): stops.append(address); uc.emu_stop()
            u.hook_add(UC_HOOK_CODE,return_stop,begin=0x30000000,end=0x30000000)
            u.emu_start(base+mouse_activity_hook_rva,0,count=50)
            held=buttons!=0
            assert stops==[0x30000000] and u.reg_read(UC_X86_REG_EAX)==(1 if held else pending)
            assert u.reg_read(UC_X86_REG_ESP)==stack+4
            assert all(u.reg_read(r)==v for r,v in regs.items() if r not in (UC_X86_REG_EAX,UC_X86_REG_EDX,UC_X86_REG_ESP))
            assert u.mem_read(mouse,len(mouse_data))==mouse_data
            assert struct.unpack('<I',u.mem_read(motion_pending,4))[0]==0
            assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==(0 if held and last_device==1 else last_device)
            assert struct.unpack('<I',u.mem_read(desktop_counter,4))[0]==int(held and last_device==1)
            tests+=1
        keyboard_ins=[]
        for ins in md.disasm(image[keyboard_activity_hook_rva:keyboard_activity_hook_rva+80],base+keyboard_activity_hook_rva):
            keyboard_ins.append(ins)
            if ins.mnemonic=='ret': break
        assert keyboard_ins and keyboard_ins[-1].mnemonic=='ret'
        keyboard_cmps=[i for i in keyboard_ins if i.bytes.startswith(b'\x83\x3d')]
        keyboard_movs=[i for i in keyboard_ins if i.bytes.startswith(b'\xc7\x05')]
        keyboard_incs=[i for i in keyboard_ins if i.mnemonic=='lock inc']
        assert len(keyboard_cmps)==len(keyboard_movs)==len(keyboard_incs)==1
        assert struct.unpack('<I',keyboard_cmps[0].bytes[2:6])[0]==last_prompt_address
        assert struct.unpack('<I',keyboard_movs[0].bytes[2:6])[0]==last_prompt_address
        keyboard_counter=struct.unpack('<I',keyboard_incs[0].bytes[3:7])[0]
        for activity,last_device in itertools.product((0,1),(0,1)):
            u=Uc(UC_ARCH_X86,UC_MODE_32)
            u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
            u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
            keyboard=0x20001000; stack=0x20008000
            keyboard_data=bytearray([0x65]*0x300); keyboard_data[0x224]=activity
            u.mem_write(keyboard,bytes(keyboard_data)); u.mem_write(stack,struct.pack('<I',0x30000000))
            u.mem_write(last_prompt_address,struct.pack('<I',last_device))
            u.mem_write(keyboard_counter,struct.pack('<I',0))
            regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                  UC_X86_REG_ECX:keyboard,UC_X86_REG_EDX:0x44556677,
                  UC_X86_REG_ESI:0x55667788,UC_X86_REG_EDI:0x66778899,
                  UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
            for reg,value in regs.items(): u.reg_write(reg,value)
            stops=[]
            def keyboard_stop(uc,address,size,user): stops.append(address); uc.emu_stop()
            u.hook_add(UC_HOOK_CODE,keyboard_stop,begin=0x30000000,end=0x30000000)
            u.emu_start(base+keyboard_activity_hook_rva,0,count=40)
            switch=activity!=0 and last_device==1
            assert stops==[0x30000000] and u.reg_read(UC_X86_REG_EAX)==((0x11223344&0xffffff00)|activity)
            assert u.reg_read(UC_X86_REG_ESP)==stack+4
            assert all(u.reg_read(r)==v for r,v in regs.items() if r not in (UC_X86_REG_EAX,UC_X86_REG_ESP))
            assert u.mem_read(keyboard,len(keyboard_data))==keyboard_data
            assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==(0 if switch else last_device)
            assert struct.unpack('<I',u.mem_read(keyboard_counter,4))[0]==int(switch)
            tests+=1
        update_ins=list(md.disasm(image[controller_update_hook_rva:controller_update_hook_rva+80],base+controller_update_hook_rva))
        update_jumps=[i for i in update_ins if i.bytes.startswith(b'\xff\x25')]
        update_calls=[i for i in update_ins if i.mnemonic=='call']
        assert len(update_jumps)==1 and len(update_calls)==1
        update_slot=struct.unpack('<I',update_jumps[0].bytes[2:6])[0]
        helper_address=int(update_calls[0].op_str,16)
        helper_rva=helper_address-base
        helper_ins=list(md.disasm(image[helper_rva:helper_rva+224],helper_address))
        helper_incs=[i for i in helper_ins if i.mnemonic=='lock inc']
        assert len(helper_incs)==1
        controller_counter=struct.unpack('<I',helper_incs[0].bytes[3:7])[0]
        for connected,pressed,stick,trigger in ((0,1,0.5,0.5),(1,0,0.0,0.0),(1,1,0.0,0.0),(1,0,0.1,0.0),(1,0,0.25,0.0),(1,0,0.0,0.15)):
            u=Uc(UC_ARCH_X86,UC_MODE_32)
            u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
            u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
            controller=0x20001000; stack=0x20008000
            controller_data=bytearray(0x300); controller_data[0x289]=connected
            struct.pack_into('<I',controller_data,0x18,pressed); struct.pack_into('<f',controller_data,0x268,stick)
            u.mem_write(controller,bytes(controller_data)); u.mem_write(stack,struct.pack('<I',0x66778899))
            u.mem_write(update_slot,struct.pack('<I',0x30000000)); u.mem_write(last_prompt_address,struct.pack('<I',0))
            u.mem_write(controller_counter,struct.pack('<I',0))
            regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                  UC_X86_REG_ECX:0x33445566,UC_X86_REG_EDX:0x44556677,
                  UC_X86_REG_ESI:controller,UC_X86_REG_EDI:0x55667788,
                  UC_X86_REG_EBP:0x778899aa,UC_X86_REG_ESP:stack}
            for reg,value in regs.items(): u.reg_write(reg,value)
            u.reg_write(UC_X86_REG_XMM1,struct.unpack('<I',struct.pack('<f',trigger))[0])
            stops=[]
            def update_stop(uc,address,size,user): stops.append(address); uc.emu_stop()
            u.hook_add(UC_HOOK_CODE,update_stop,begin=0x30000000,end=0x30000000)
            u.emu_start(base+controller_update_hook_rva,0,count=500)
            meaningful=bool(connected and (pressed or abs(stick)>0.20 or abs(trigger)>0.10))
            controller_data[0x27c:0x280]=struct.pack('<f',trigger)
            assert stops==[0x30000000] and u.mem_read(controller,len(controller_data))==controller_data
            assert u.reg_read(UC_X86_REG_ESP)==stack+4 and u.reg_read(UC_X86_REG_EDI)==0x66778899
            assert all(u.reg_read(r)==v for r,v in regs.items() if r not in (UC_X86_REG_EDI,UC_X86_REG_ESP))
            assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==0
            assert struct.unpack('<I',u.mem_read(controller_counter,4))[0]==int(meaningful)
            tests+=1
        u=Uc(UC_ARCH_X86,UC_MODE_32)
        u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
        u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
        controller=0x20001000; stack=0x20008000
        controller_data=bytearray(0x300); controller_data[0x289]=1
        struct.pack_into('<f',controller_data,0x268,0.5)
        u.mem_write(controller,bytes(controller_data)); u.mem_write(update_slot,struct.pack('<I',0x30000000))
        u.mem_write(last_prompt_address,struct.pack('<I',0)); u.mem_write(controller_counter,struct.pack('<I',0))
        update_regs={UC_X86_REG_EAX:0x11223344,UC_X86_REG_EBX:0x22334455,
                     UC_X86_REG_ECX:0x33445566,UC_X86_REG_EDX:0x44556677,
                     UC_X86_REG_ESI:controller,UC_X86_REG_EDI:0x55667788,
                     UC_X86_REG_EBP:0x778899aa}
        stops=[]
        def held_stop(uc,address,size,user): stops.append(address); uc.emu_stop()
        u.hook_add(UC_HOOK_CODE,held_stop,begin=0x30000000,end=0x30000000)
        def run_controller_update():
            u.mem_write(stack,struct.pack('<I',0x66778899)); u.reg_write(UC_X86_REG_ESP,stack)
            for reg,value in update_regs.items(): u.reg_write(reg,value)
            u.reg_write(UC_X86_REG_XMM1,0); stops.clear()
            u.emu_start(base+controller_update_hook_rva,0,count=500)
            assert stops==[0x30000000]
        run_controller_update()
        assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==0
        assert struct.unpack('<I',u.mem_read(controller_counter,4))[0]==1
        tests+=1
        u.mem_write(last_prompt_address,struct.pack('<I',0)); run_controller_update()
        assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==0
        assert struct.unpack('<I',u.mem_read(controller_counter,4))[0]==1
        tests+=1
        u.mem_write(controller+0x268,struct.pack('<f',0.7)); run_controller_update()
        assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==0
        assert struct.unpack('<I',u.mem_read(controller_counter,4))[0]==2
        tests+=1
        # Controller activity is observed for diagnostics but cannot change the
        # KBM prompt preference in this variant.
        u=Uc(UC_ARCH_X86,UC_MODE_32)
        u.mem_map(base,(len(image)+4095)&~4095); u.mem_write(base,image)
        u.mem_map(0x20000000,0x10000); u.mem_map(0x30000000,0x1000)
        controller=0x20001000; stack=0x20008000
        controller_data=bytearray(0x300); controller_data[0x289]=1
        struct.pack_into('<I',controller_data,0x18,1)
        u.mem_write(controller,bytes(controller_data)); u.mem_write(update_slot,struct.pack('<I',0x30000000))
        u.mem_write(last_prompt_address,struct.pack('<I',0)); u.mem_write(controller_counter,struct.pack('<I',0))
        stops=[]
        def held_stop(uc,address,size,user): stops.append(address); uc.emu_stop()
        u.hook_add(UC_HOOK_CODE,held_stop,begin=0x30000000,end=0x30000000)
        run_controller_update()
        assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==0
        assert struct.unpack('<I',u.mem_read(controller_counter,4))[0]==1
        tests+=1
        u.mem_write(last_prompt_address,struct.pack('<I',0)); run_controller_update()
        assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==0
        assert struct.unpack('<I',u.mem_read(controller_counter,4))[0]==2
        tests+=1
        u.mem_write(controller+0x18,struct.pack('<I',0)); run_controller_update()
        u.mem_write(controller+0x18,struct.pack('<I',1)); run_controller_update()
        assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==0
        assert struct.unpack('<I',u.mem_read(controller_counter,4))[0]==3
        tests+=1
        u.mem_write(controller+0x289,b'\x00'); run_controller_update()
        u.mem_write(last_prompt_address,struct.pack('<I',0))
        u.mem_write(controller+0x289,b'\x01'); run_controller_update()
        assert struct.unpack('<I',u.mem_read(last_prompt_address,4))[0]==0
        assert struct.unpack('<I',u.mem_read(controller_counter,4))[0]==4
        tests+=1
    report={'status':'offline validation passed; gameplay NOT tested',
            'architecture':'x86 / PE32 / 0x14c', 'plugin_sha256':sha(artifact),
             'variant':'KBM prompts',
             'source_sha256':sha(DEV/'src/MixedInputKBMPrompts.cpp'),
            'plugin_bytes':artifact.stat().st_size,'imports':imports,
            'context_unique_rvas':['0x57cc10','0x57cd4f','0x57cd89','0x57cdc0','0x57d6c0','0x57d454','0x42d044','0x60e99c','0x9bbe70','0x60ee00','0x60f264'],
            'patch_rvas':['0x57cc16','0x57cd5a','0x57cd99','0x57cdc5','0x57d6d4','0x57d476','0x42d04e','0x60e99c','0x9bbe70','0x60ee00','0x60f264'],
            'hook_rvas':[hex(hook_rva),hex(desktop_hook_rva),hex(controller_hook_rva),hex(route_hook_rva),hex(axis_hook_rva),hex(prompt_hook_rva),hex(prompt_mode_hook_rva),hex(raw_mouse_hook_rva),hex(mouse_activity_hook_rva),hex(keyboard_activity_hook_rva),hex(controller_update_hook_rva)],
            'synthetic_hook_tests':tests,
            'existing_save_mod_target_rva':hex(skip_rva),
            'protected_originals':originals}
    (DEV/'analysis').mkdir(exist_ok=True)
    (DEV/'analysis/validation-kbm.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return artifact

if __name__=='__main__':
    validate()
