#############################################################################
#
# This is a set of utilities that is supposed to help
# analyzing core files from crashes of the hotspot vm with GDB
#
#############################################################################

import gdb
import pdb

#############################################################################
# PROVIDED FUNCTIONS
#############################################################################
#
# ---------------------------------------------------------------------
# CC_find_blob_unsafe: Find a nmethod for a given pc 
# ---------------------------------------------------------------------
#
# Example:
#
#    (gdb) print $CC_find_blob_unsafe(0x0000008006424c08)
#    {(methodOopDesc *)0x21de4db8}:sun/font/AttributeValues.merge(Ljava/util/Map;I)Lsun/font/AttributeValues;
#    $13 = (nmethod *) 0x8006424310
#
# ---------------------------------------------------------------------
# NM_pc_desc_at: get the PcDesc for a given pc
# ---------------------------------------------------------------------
# 
# Example:
#
#    (gdb) print $NM_pc_desc_at(0x0000008006424c08)
#    $5 = (PcDesc *) 0x8006428488
#
#
# ---------------------------------------------------------------------
# NM_print_inlining_at: print inlining at the given compiled pc
# ---------------------------------------------------------------------
# 
# Example:
#
#    (gdb) print $NM_print_inlining_at(0x00002aaaad53db7f)
#    {(methodOopDesc *)0x901a1ea0}:java/lang/ThreadLocal.access$400(Ljava/lang/ThreadLocal;)I:bci1/L53
#    {(methodOopDesc *)0x902b4300}:java/lang/ThreadLocal$ThreadLocalMap.getEntry(Ljava/lang/ThreadLocal;)Ljava/lang/ThreadLocal$ThreadLocalMap$Entry;:bci1/L357
#    {(methodOopDesc *)0x902b5250}:java/lang/ThreadLocal$ThreadLocalMap.access$000(Ljava/lang/ThreadLocal$ThreadLocalMap;Ljava/lang/ThreadLocal;)Ljava/lang/ThreadLocal$ThreadLocalMap$Entry;:bci2/L242
#    {(methodOopDesc *)0x901a1698}:java/lang/ThreadLocal.get()Ljava/lang/Object;:bci16/L127
#    {(methodOopDesc *)0x905a88c8}:java/math/BigDecimal.layoutChars(Z)Ljava/lang/String;:bci39/L3264
#
#
# ---------------------------------------------------------------------
# COMP_find_ir_node: find the Node* corresponging to the provided
#                    Compile object and node idx
# ---------------------------------------------------------------------
# 
# Example:
#
#    (gdb) print $COMP_find_ir_node((class Compile * const) 0x4005a35d4a0, 229)
#    $26 = (Node *) 0x10155630
#
#############################################################################


#############################################################################
#############################################################################
## IMPLEMENTATION
#############################################################################
#############################################################################


#############################################################################
#
# Hotspot types
#
#############################################################################
char_t  = gdb.lookup_type('char')                             # char
jbyte_t   = gdb.lookup_type('jbyte')                          # jbyte
jubyte_t   = gdb.lookup_type('jubyte')                        # jubyte
int_t   = gdb.lookup_type('int')                              # int
int_tp   = int_t.pointer()                                    # int
long_t   = gdb.lookup_type('long')                            # long
jint_t   = gdb.lookup_type('jint')                            # jint
juint_t   = gdb.lookup_type('juint')                          # juint
uint_t   = gdb.lookup_type('unsigned int')                    # unsigned int
intptr_t  = gdb.lookup_type('intptr_t')                       # intptr_t
u_char_t= gdb.lookup_type('unsigned char')                    # u_char
u_char_tp= u_char_t.pointer()                                 # u_char*
void_tp = gdb.lookup_type('void').pointer()                   # void*
char_tp = char_t.pointer()                                    # char*
intptr_tp  = intptr_t.pointer()                               # intptr*
address_t = gdb.lookup_type('address')                        # address_t
address_tp = address_t.pointer()                              # address_t
size_t = gdb.lookup_type('size_t')                            # size_t
ptrdiff_t = gdb.lookup_type('ptrdiff_t')                      # ptrdiff_t
HeapBlock_tp = gdb.lookup_type('HeapBlock').pointer()         # HeapBlock*
CodeHeap_tp = gdb.lookup_type('CodeHeap').pointer()           # CodeHeap*
CodeBlob_tp = gdb.lookup_type('CodeBlob').pointer()           # CodeBlob*
nmethod_tp = gdb.lookup_type('nmethod').pointer()             # nmethod*
PcDescCache_tp = gdb.lookup_type('PcDescCache').pointer()     # PcDescCache*
PcDesc_tp = gdb.lookup_type('PcDesc').pointer()               # PcDesc*
constantPoolOopDesc_t = gdb.lookup_type('constantPoolOopDesc')# constantPoolOopDesc
Klass_t = gdb.lookup_type('Klass')                            # Klass
oop_t = gdb.lookup_type('oop')                                # oop
methodOop_t = gdb.lookup_type('methodOop')                    # methodOop
constMethodOop_t = gdb.lookup_type('constMethodOop')          # constMethodOop
constantPoolOop_t = gdb.lookup_type('constantPoolOop')        # constantPoolOop
klassOop_t = gdb.lookup_type('klassOop')                      # klassOop
symbolOop_t = gdb.lookup_type('symbolOop')                    # symbolOop
Klass_tp = gdb.lookup_type('Klass').pointer()                 # Klass*
oop_tp = gdb.lookup_type('oop').pointer()                     # oop*
Compile_tp = gdb.lookup_type('Compile').pointer()             # Compile*
Node_tp = gdb.lookup_type('Node').pointer()                   # Node*
RegionNode_tp = gdb.lookup_type('RegionNode').pointer()       # RegionNode*
LoopNode_tp = gdb.lookup_type('LoopNode').pointer()           # LoopNode*
RootNode_tp = gdb.lookup_type('RootNode').pointer()           # RootNode*

# global definitions from globalDefinitions.hpp
badInt           = gdb.parse_and_eval('-3').cast(jint_t);                       # generic "bad int" value
badAddressVal    = gdb.parse_and_eval('-2').cast(long_t);                       # generic "bad address" value
badOopVal        = gdb.parse_and_eval('-1').cast(long_t);                       # generic "bad oop" value
badHeapOopVal    = gdb.parse_and_eval('(intptr_t) 0x2BAD4B0BBAADBABELL').cast(intptr_t); # value used to zap heap after GC
badHandleValue   = gdb.parse_and_eval('0xBC').cast(int_t);                     # value used to zap vm handle area
badResourceValue = gdb.parse_and_eval('0xAB').cast(int_t);                     # value used to zap resource area
freeBlockPad     = gdb.parse_and_eval('0xBA').cast(int_t);                     # value used to pad freed blocks.
uninitBlockPad   = gdb.parse_and_eval('0xF1').cast(int_t);                     # value used to zap newly malloc'd blocks.
badJNIHandleVal  = gdb.parse_and_eval('(intptr_t) 0xFEFEFEFEFEFEFEFELL').cast(intptr_t); # value used to zap jni handle area
badHeapWordVal   = gdb.parse_and_eval('0xBAADBABE').cast(juint_t);               # value used to zap heap after GC
badCodeHeapNewVal= gdb.parse_and_eval('0xCC').cast(int_t);                     # value used to zap Code heap at allocation
badCodeHeapFreeVal = gdb.parse_and_eval('0xDD').cast(int_t);                   # value used to zap Code heap at deallocation

badAddress       = badAddressVal.cast(intptr_t).cast(address_t)
badOop           = badOopVal.cast(intptr_t).cast(oop_t)
badHeapWord      = badHeapWordVal
badJNIHandle     = badJNIHandleVal.cast(oop_t)


class JavaValue(object):
    InvocationEntryBci = gdb.Value(-1).cast(int_t)
    InvalidOSREntryBci = gdb.Value(-2).cast(int_t)

#############################################################################
#
# tracing/debugging support for this python module
#
#############################################################################

#
# PYTHON DEBUGGING
#
# It's easy, e.g. add a new line 'pdb.set_trace()' where you want to
# start debugging. When execution reaches that line, pdb (interactive
# python debugger) gets activated. Read http://docs.python.org/library/pdb.html
# how to use it!
#
# Or start a post mortem analysis by typing py pdb.pm() at the (gdb) prompt:
#
#    TypeError: pc_desc_at() takes exactly 3 arguments (2 given)
#    Error while executing Python code.
#    (gdb) py pdb.pm()
#    > [some path...]
#    -> res = nm.pc_desc_at(pc)
#    (Pdb) 
#

# pretty print a gdb.Value when debugging with pdb (python debugger)
#
# Example
#
#   (Pdb) p nm
#   <__main__.nmethod object at 0xe8be1150>
#
#   (Pdb) gpp(nm)
#   {(methodOopDesc *)0x21de4db8}:sun/font/AttributeValues.merge(Ljava/util/Map;I)Lsun/font/AttributeValues;
#
def gpp(val, newline = True):
    if (   isinstance(val, methodOop)
        or isinstance(val, nmethod)):
        s = val.extended_str()
    else:
        s = gdbval2str(val)
    gdb.write(s)
    if newline: print

# get a human readable string respresentation of a gdb.Value
def gdbval2str(val):
    res = str(val)
    if isinstance(val, gdb.Value):
        # include type for pointers or when printing verbose
        res = "(" + str(val.type) + ")" + res
    return res


#############################################################################
#
# GdbValWrapper
#
#############################################################################

# Instances of GdbValWrapper wrap a gdb.Value object. Subclasses
# provide methods That operate on the value. E.g. CodeHeap wraps a
# (CodeHeap*) value and CodeHeap.find_start(addr) finds the element on
# the heap that contains the given addr and returns the start address
# of that element.
#
# The class is actually just needed because gdb.Value cannot be subclassed.
#
# Subclassing GdbValWrapper...
#
# ...is easy: just make sure you provide a constructor that takes a gdb.Value
# and its gdb.Type as an optional parameter, with T as default Value, where
# T is the gdb.Type of the values the new subclass is wrapping. The constructor
# must call the constructor of its superclass passing value and type:
#
#   class <subclass name>(GdbValWrapper):
#       def __init__(self, klass, gdbtype = T):
#           super(<subclass name>, self).__init__(klass, gdbtype)
#   
#
#
class GdbValWrapper(object):
    def __init__(self, gdbval, gdbtype = void_tp):
        if not isinstance(gdbval, gdb.Value):
            # GdbValWrapper is for gdv.Values only!
            raise Exception(repr(gdbval) + " is not an gdb.Value instance!")
        self._gdbval = gdbval.cast(gdbtype)
    def __str__(self):
        return "{"+gdbval2str(self._gdbval)+"}"
    #
    # operators: delegate to the wrapped gdb.Value
    #
    def __eq__(self, other): return self.unwrap() == other.unwrap()
    def __ne__(self, other): return self.unwrap() != other.unwrap()
    def __lt__(self, other): return self.unwrap() <  other.unwrap()
    def __le__(self, other): return self.unwrap() <= other.unwrap()
    def __ge__(self, other): return self.unwrap() >= other.unwrap()
    def __gt__(self, other): return self.unwrap() >  other.unwrap()
    # pointer arithmetics
    def __add__(self, val):
        new_gdb_val = self.unwrap() + val # delegate to gdb.Value
        res = self.__class__(new_gdb_val) # construct new wrapper
        return res
    def __sub__(self, val):
        new_gdb_val = self.unwrap() - val # delegate to gdb.Value
        res = self.__class__(new_gdb_val) # construct new wrapper
        return res
    # return the wrapped value
    def unwrap(self): return self._gdbval
    def getField(self, name): return self._gdbval[name]
        
# Constants
NULL = GdbValWrapper(gdb.Value(0),void_tp)


#############################################################################
# Klass
#############################################################################

class Klass(GdbValWrapper):
    def __init__(self, klass, gdbtype = Klass_tp):
        super(Klass, self).__init__(klass, gdbtype)
        self._name = symbolOop(self.getField('_name'))
    def extended_str(self):
        if self._name != NULL: return self._name.extended_str()
        else: return "special klass (e.g. klassKlass)"

#############################################################################
# oop
#############################################################################

class oop(GdbValWrapper):
    def __init__(self, oopVal, gdbtype = oop_t):
        super(oop, self).__init__(oopVal, gdbtype)


#############################################################################
# klassOop
#############################################################################

class klassOop(oop):
    def __init__(self, koop, gdbtype = klassOop_t):
        super(klassOop, self).__init__(koop, gdbtype)
    def klass_part(self):
        res = Klass((self+1).unwrap())
        return res
    def extended_str(self):
        return self.klass_part().extended_str()
        
#############################################################################
# symbolOop
#############################################################################

class symbolOop(oop):
    def __init__(self, soop, gdbtype = symbolOop_t):
        super(symbolOop, self).__init__(soop, gdbtype)
    def extended_str(self):
        return self.getField('_body').address.cast(char_tp).string()

        
#############################################################################
# constantPoolOop
#############################################################################

class constantPoolOop(oop):
    def __init__(self, cpoop, gdbtype = constantPoolOop_t):
        super(constantPoolOop, self).__init__(cpoop, gdbtype)
    def pool_holder(self):
        return klassOop(self.getField('_pool_holder'))
        
#############################################################################
# methodOop
#############################################################################

class constMethodOop(oop):
    _has_linenumber_table = 1
    _has_checked_exceptions = 2
    _has_localvariable_table = 4
    def __init__(self, cmoop, gdbtype = constMethodOop_t):
        super(constMethodOop, self).__init__(cmoop, gdbtype)
    def code_base(self): return (self+1).unwrap().cast(address_t)
    def code_end(self): return self.code_base() + self.code_size()
    def code_size(self): return self.getField('_code_size')
    def has_linenumber_table(self):
        return (self.getField('_flags') & constMethodOop._has_linenumber_table) != 0
    def compressed_linenumber_table(self):
        # Located immediately following the bytecodes.
        assert self.has_linenumber_table(), "called only if table is present"
        res = self.code_end()
        return res

#############################################################################
# methodOop
#############################################################################

class methodOop(oop):
    def __init__(self, moop, gdbtype = methodOop_t):
        super(methodOop, self).__init__(moop, gdbtype)
        self._constants = constantPoolOop(self.getField('_constants'))
        self._constMethod = constMethodOop(self.getField('_constMethod'))
    def constMethod(self): return self._constMethod
    def code_size(self): return self._constMethod.code_size()
    def has_linenumber_table(self): return self.constMethod().has_linenumber_table()
    def compressed_linenumber_table(self): return self.constMethod().compressed_linenumber_table()
    def line_number_from_bci(self, bci):
        assert bci == 0 or (0 <= bci and bci < self.code_size()), "illegal bci"
        best_bci  =  0
        best_line = -1

        if (self.has_linenumber_table()):
          # The line numbers are a short array of 2-tuples [start_pc, line_number].
          # Not necessarily sorted and not necessarily one-to-one.
            stream = CompressedLineNumberReadStream(self.compressed_linenumber_table())
            while (stream.read_pair()):
                if (stream.bci() == bci):
                    # perfect match
                    return stream.line()
                else:
                    # update best_bci/line
                    if (stream.bci() < bci and stream.bci() >= best_bci):
                        best_bci  = stream.bci()
                        best_line = stream.line()
        return best_line

    def extended_str(self):
        res = self.__str__() + ':'

        cpool_base = (self._constants.unwrap().cast(char_tp)
                      + constantPoolOopDesc_t.sizeof).cast(intptr_tp)

        # print holder klass
        holder = self._constants.pool_holder()
        res += holder.extended_str()+ '.'

        # print the name
        sig_idx = self._constMethod.getField('_name_index')
        addr_in_cpool = ((cpool_base)[sig_idx]).address
        nameSymOop = symbolOop(addr_in_cpool.cast(oop_tp).dereference())
        res += nameSymOop.extended_str()

        # print the signature
        sig_idx = self._constMethod.getField('_signature_index')
        addr_in_cpool = ((cpool_base)[sig_idx]).address
        sigSymOop = symbolOop(addr_in_cpool.cast(oop_tp).dereference())
        res += sigSymOop.extended_str()
        return res



#############################################################################
#
# _GrowableArray provides similar functionality as GrowableArray.
#
# NOTE: It does *not* represent an instance of GrowableArray in the
# hotspot debuggee. Use GrowableArray for that purpose!
#
#############################################################################

# TODO: is list good enough as a _GrowableArray?
class _GrowableArray(list):
    def __init__(self):
        super(_GrowableArray, self).__init__()
    def at(self, i):
        return self[i]
    def length(self): return len(self)
    def contains(self, elm): return elm in self
    def __str__(self): return super(_GrowableArray, self).__str__()

#############################################################################
#
# macros for CodeCache/CodeHeap
#
#############################################################################

# ---------------------------------------------------------------------
# CC_find_blob_unsafe: Find a nmethod for a given pc 
# ---------------------------------------------------------------------
#
# Example:
#
#    (gdb) print $CC_find_blob_unsafe(0x0000008006424c08)
#    {(methodOopDesc *)0x21de4db8}:sun/font/AttributeValues.merge(Ljava/util/Map;I)Lsun/font/AttributeValues;
#    $13 = (nmethod *) 0x8006424310
#
class CC_find_blob_unsafe (gdb.Function):
    """TODO: Documentation for CC_find_blob_unsafe"""

    def __init__(self):
        super (CC_find_blob_unsafe, self).__init__("CC_find_blob_unsafe")

    def invoke (self, start):
        res = CodeCache.find_blob_unsafe(start)
        if res != NULL:
            if res.is_nmethod():
                res = res.as_nmethod()
                gpp(res)
            res = res.unwrap()
        return res

CC_find_blob_unsafe()

class VirtualSpace(object):
    def __init__(self, low, high):
        self._low  = low
        self._high = high
    def __str__(self): return "VirtualSpace[" + gdbval2str(self._low) + "," + gdbval2str(self._high) + "]"
    def low(self): return self._low
    def high(self): return self._high

class HeapBlock(GdbValWrapper):
    def __init__(self, block, gdbtype = HeapBlock_tp):
        super(HeapBlock, self).__init__(block, gdbtype)
    def free(self):
        res = not (self.getField('_header')['_used'])
        return res
    def allocated_space(self):
        res = (self + 1).unwrap().cast(void_tp)
        return res

class CodeHeap(GdbValWrapper):
    def __init__(self, heap, gdbtype = CodeHeap_tp):
        super(CodeHeap, self).__init__(heap, gdbtype)
        self._memory   = VirtualSpace(heap['_memory']['_low'], heap['_memory']['_high'])
        self._segmap   = VirtualSpace(heap['_segmap']['_low'], heap['_segmap']['_high'])
        self._log2_segment_size = heap['_log2_segment_size']
    def begin(self):
        res = self._memory.low()
        return res
    def end(self):
        res = self._memory.high()
        return res
    def contains(self, p):
        res = self.begin() <= p and p < self.end()
        return res
    def segment_for(self, p):
        res = ((p.cast(char_tp) - self._memory.low()) >> self._log2_segment_size).cast(size_t)
        return res
    def block_at(self, i):
        res = (self._memory.low() + (i << self._log2_segment_size)).cast(HeapBlock_tp)
        return HeapBlock(res)
    def find_start(self, p):
        if not self.contains(p):
            return 0
        
        i = self.segment_for(p)

        b = self._segmap.low().cast(address_t)
        if b[i] == 0xFF:
            return NULL
        while b[i] > 0:
            i -= b[i].cast(int_t)

        h = self.block_at(i)

        if h.free():
            return NULL

        return h.allocated_space()

class CodeBlob(GdbValWrapper):
    def __init__(self, blob, gdbtype = CodeBlob_tp):
        super(CodeBlob, self).__init__(blob, gdbtype)
        self._size                    = self.getField('_size')
        self._instructions_offset     = self.getField('_instructions_offset')
    def header_begin(self):
        res = self.unwrap().cast(address_t)
        return res
    def data_end(self):
        res = (self.header_begin() + self._size).cast(address_t)
        return res
    def instructions_begin(self):
        res = self.header_begin() + self._instructions_offset
        return res
    def blob_contains(self, addr):
        res = self.header_begin() <= addr and addr < self.data_end()
        return res
    def oop_at(self, index):
        index = index.cast(int_t)
        if index == 0: return NULL
        return self.oop_addr_at(index).dereference()
    def oop_addr_at(self, index):
        begin = self.oops_begin()
        oopat_idx = begin[index-1]
        res = oopat_idx.address
        return res
    def is_nmethod(self):
        return self.getField('_name').string() == "nmethod"
    def as_nmethod(self):
        assert self.is_nmethod(), gdbval2str(self) + " is not a nmethod"
        return nmethod(self.unwrap())

class CodeCache(object):
    @staticmethod 
    def find_blob_unsafe(start):
        heapAsGdbVal = gdb.parse_and_eval("CodeCache::_heap")
        _heap = CodeHeap(heapAsGdbVal)
        result = CodeBlob(_heap.find_start(start))

        if result != NULL and not result.blob_contains(start.cast(address_t)):
            result = NULL

        return result

#############################################################################
#
# Analyzing nmethods
#
#############################################################################

class NM_print_inlining_at (gdb.Function):
    """TODO: Documentation for NM_print_inlining_at"""
    def __init__(self):
        super (NM_print_inlining_at, self).__init__("NM_print_inlining_at")
    def invoke (self, pc):
        pc = pc.cast(address_t)
        blob = CodeCache.find_blob_unsafe(pc)
        if blob == NULL or not blob.is_nmethod(): return NULL
        nm = blob.as_nmethod()
        pcdesc = nm.pc_desc_at(pc, False)
        if (pcdesc == NULL):
            print "No pcdesc found for " + gdbval2str(pc)
            print "Looking for approximate..."
            pcdesc = nm.pc_desc_at(pc, True)
        if (pcdesc == NULL):
            print "No approximate pcdesc found for " + gdbval2str(pc)
            return NULL

        # ported from java_lang_Throwable::fill_in_stack_trace(Handle throwable, TRAPS)
        decode_offset = pcdesc.scope_decode_offset()
        while (decode_offset != 0):
            stream = DebugInfoReadStream(nm, decode_offset)
            decode_offset = stream.read_int()
            method = methodOop(nm.oop_at(stream.read_int()))
            bci = stream.read_bci()
            line = method.line_number_from_bci(bci)
            gdb.write(method.extended_str() + ":bci"+str(bci) + "/L" + str(line))
            print

        return gdb.Value(0) # success

NM_print_inlining_at()

class CompressedStream(object):
    BitsPerByte = 8
    lg_H = gdb.Value(6)
    H = 1<<lg_H
    L = (1<<BitsPerByte)-H
    MAX_i = 4
    def __init__(self, buffer, position):
        self._buffer   = buffer.cast(u_char_tp)
        self._position = position
    def position(self): return self._position
    def set_position(self, position): self._position = position
    def buffer(self):   return self._buffer
        
class CompressedReadStream(CompressedStream):
    def __init__(self, buffer, position = gdb.Value(0)):
        super(CompressedReadStream, self).__init__(buffer, position)
    def read(self):
        res = self._buffer[self._position]
        self._position += 1
        return res
    def read_byte(self): return self.read().cast(jbyte_t)
    def decode_sign(self, value):
        value = value.cast(juint_t)
        res = ((value >> 1) ^ (-((value & 1).cast(jint_t)))).cast(jint_t)
        return res
    def read_signed_int(self): return self.decode_sign(self.read_int())
    def read_int_mb(self, b0):
        b0 = b0.cast(jint_t)
        pos = self.position() - 1
        buf = self.buffer() + pos
        assert buf[0] == b0 and b0 >= CompressedStream.L, "correctly called"
        sum = b0.cast(jint_t)
        # must collect more bytes:  b[1]...b[4]
        lg_H_i = CompressedStream.lg_H.cast(int_t)
        i = gdb.Value(0).cast(int_t)
        while True:
            i += 1
            b_i = buf[i].cast(jint_t) # b_i = read(); ++i;
            sum += b_i << lg_H_i  # sum += b[i]*(64**i)
            if (b_i < CompressedStream.L or i == CompressedStream.MAX_i):
                self.set_position(pos+i+1)
                return sum
            lg_H_i += lg_H

    def read_int(self):
        b0 = self.read()
        if (b0 < CompressedStream.L):  return b0
        else:         return self.read_int_mb(b0)

class CompressedLineNumberReadStream(CompressedReadStream):
    def __init__(self, buf):
        super(CompressedLineNumberReadStream, self).__init__(buf)
        self._bci = gdb.Value(0)
        self._line = gdb.Value(0)
    def bci(self): return self._bci
    def line(self): return self._line
    def read_pair(self):
        next = self.read_byte().cast(jubyte_t)
        # Check for terminator
        if (next == 0): return False
        if (next == 0xFF):
            # Escape character, regular compression used
            self._bci  += self.read_signed_int()
            self._line += self.read_signed_int()
        else:
            # Single byte compression used
            self._bci  += next >> 3
            self._line += next & 0x7
        return True

class DebugInfoReadStream(CompressedReadStream):
    def __init__(self, code, offset, obj_pool = NULL):
        super(DebugInfoReadStream, self).__init__(code.scopes_data_begin(), offset)
        self._code = code
        self._obj_pool = obj_pool
    def read_bci(self):
        return self.read_int() + JavaValue.InvocationEntryBci

class NM_pc_desc_at (gdb.Function):
    """TODO: Documentation for NM_pc_desc_at"""
    def __init__(self):
        super (NM_pc_desc_at, self).__init__("NM_pc_desc_at")
    def invoke (self, pc):
        blob = CodeCache.find_blob_unsafe(pc)
        if blob == NULL or not blob.is_nmethod(): return NULL
        nm = blob.as_nmethod()
        res = nm.pc_desc_at(pc)
        if (res == NULL): return NULL.cast(PcDesc_tp)
        return res.unwrap()

NM_pc_desc_at()

class nmethod(CodeBlob):
    def __init__(self, nm, gdbtype = nmethod_tp):
        super (nmethod, self).__init__(nm, gdbtype)
        self._pc_desc_cache = PcDescCache(self.getField('_pc_desc_cache').address)
        self._scopes_pcs_offset   = self.getField('_scopes_pcs_offset')
        self._dependencies_offset = self.getField('_dependencies_offset')
        self._scopes_data_offset = self.getField('_scopes_data_offset')
        self._scopes_pcs_begin  = (self.header_begin() + self._scopes_pcs_offset).cast(PcDesc_tp)
        self._scopes_pcs_end    = (self.header_begin() + self._dependencies_offset).cast(PcDesc_tp)
        self._scopes_data_begin = (self.header_begin() + self._scopes_data_offset).cast(address_t)
        self._oops_offset     = self.getField('_oops_offset')
    def oops_begin(self):
        res = (self.header_begin() + self._oops_offset).cast(oop_tp)
        return res
    def scopes_data_begin(self):
        res = self._scopes_data_begin
        return res
    def scopes_pcs_begin(self):
        res = PcDesc(self._scopes_pcs_begin)
        return res
    def scopes_pcs_end(self):
        res = PcDesc(self._scopes_pcs_end)
        return res
    def find_pc_desc_internal(self, pc, approximate):
        base_address = self.instructions_begin()
        if ((pc < base_address) or
            (pc - base_address) >= PcDesc.upper_offset_limit.cast(ptrdiff_t)):
            return NULL  # PC is wildly out of range

        pc_offset = (pc - base_address).cast(int_t)

        # Check the PcDesc cache if it contains the desired PcDesc
        # (This as an almost 100% hit rate.)
        res = self._pc_desc_cache.find_pc_desc(pc_offset, approximate)
        if (res != NULL):
            return res

        # Fallback algorithm: quasi-linear search for the PcDesc
        # ...
        lower = self.scopes_pcs_begin()
        upper = self.scopes_pcs_end()
        upper -= 1 # exclude final sentinel

        if (lower >= upper):  return NULL  # native method; no PcDescs at all

        # Use the last successful return as a split point.
        mid = self._pc_desc_cache.last_pc_desc()
        if (mid.pc_offset() < pc_offset):
            lower = mid
        else:
            upper = mid

        # Take giant steps at first (4096, then 256, then 16, then 1)
        LOG2_RADIX = 3 # /*smaller steps in debug mode:*/ debug_only(-1)
        # dead: RADIX = (1 << LOG2_RADIX)
        step = (1 << (LOG2_RADIX*3))
        while (step > 1):
            mid = lower + step

            while (mid < upper):
                if (mid.pc_offset() < pc_offset):
                    lower = mid
                else:
                    upper = mid
                    break
                mid = lower + step
            step = step >> LOG2_RADIX 


        # Sneak up on the value with a linear search of length ~16.
        while True:
            mid = lower + 1
            if (mid.pc_offset() < pc_offset):
                lower = mid
            else:
                upper = mid
                break


        if (match_desc(upper, pc_offset, approximate)):
            return upper
        else:
            return NULL
    def find_pc_desc(self, pc, approximate):
        desc = self._pc_desc_cache.last_pc_desc()
        if desc != NULL and desc.pc_offset() == pc - self.instructions_begin():
            return desc
        return self.find_pc_desc_internal(pc, approximate)
    def pc_desc_at(self, pc, approximate = False):
        pc = pc.cast(address_t)
        res =  self.find_pc_desc(pc, approximate)
        if res != NULL: return res
        # not found -> approximate
        return self.find_pc_desc(pc, True) 
    def method(self): return methodOop(self.getField('_method'))
    def extended_str (self):
        return self.__str__() + ':' + self.method().extended_str()

def match_desc(pc, pc_offset, approximate):
    if (not approximate):
        return pc.pc_offset() == pc_offset
    else:
        return (pc-1).pc_offset() < pc_offset and pc_offset <= pc.pc_offset()

class PcDescCache(GdbValWrapper):
    cache_size = 4
    def __init__(self, cache, gdbtype = PcDescCache_tp):
        super (PcDescCache, self).__init__(cache, gdbtype)
        self._last_pc_desc = PcDesc(self.getField("_last_pc_desc"))
        self._pc_descs = self.getField("_pc_descs")
    def last_pc_desc(self): return self._last_pc_desc
    def find_pc_desc(self, pc_offset, approximate):
        res = self._last_pc_desc
        if (res == NULL):  return NULL  # native method; no PcDescs at all

        if (match_desc(res, pc_offset, approximate)):
            return res

        # Step two:  Check the LRU cache.
        i = 0
        while i < PcDescCache.cache_size:
            res = PcDesc(self._pc_descs[i])
            if (res.pc_offset() < 0):  break  # optimization: skip empty cache
            if (match_desc(res, pc_offset, approximate)):
                # _last_pc_desc = res;  // record this cache hit in case of repeat
                return res
            i += 1

        # Report failure.
        return NULL

class PcDesc(GdbValWrapper):
    lower_offset_limit = gdb.Value(-1)
    upper_offset_limit = gdb.Value(-1).cast(uint_t) >> 1
    def __init__(self, desc, gdbtype = PcDesc_tp):
        super (PcDesc, self).__init__(desc, gdbtype)
    def pc_offset(self): return self.getField("_pc_offset")
    def scope_decode_offset(self): return self.getField("_scope_decode_offset")
    
