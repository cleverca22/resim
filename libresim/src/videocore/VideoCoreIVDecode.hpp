
#ifndef RESIM_VIDEOCOREIVDECODE_HPP_INCLUDED
#define RESIM_VIDEOCOREIVDECODE_HPP_INCLUDED

#include "Memory.hpp"
#include "videocore/VideoCoreIVRegisterFile.hpp"
#include "VideoCoreIVExecute.hpp"

int32_t extendSigned(int32_t value, uint32_t msbMask) {
	if ((value & msbMask) != 0) {
		return value | ~(msbMask | (msbMask - 1));
	} else {
		return value;
	}
}

class VideoCoreIVDecode {
public:
	VideoCoreIVDecode(Memory *memory,
	                  VideoCoreIVRegisterFile &registers,
                          VectorFile &vector_file,
	                  Log *log)
			: memory(memory), registers(registers), vector_file(vector_file), log(log),
			execute(memory, registers, log) {
	}

	void step() {
		log->debug("vc4", "pc: %08x", pc());
		Memory::setCurrentInstr(pc());
		uint16_t inst1 = memory->readHalfWord(pc());
		if ((inst1 & 0x8000) == 0) {              // 0??? ????  ???? ????
			scalar16(inst1);
		} else if ((inst1 & 0xc000) == 0x8000) {  // 10?? ????  ???? ????
			uint16_t inst2 = memory->readHalfWord(pc() + 2);
			scalar32(inst1, inst2);
		} else if ((inst1 & 0xe000) == 0xc000) {  // 110? ????  ???? ????
			uint16_t inst2 = memory->readHalfWord(pc() + 2);
			scalar32(inst1, inst2);
		} else if ((inst1 & 0xf000) == 0xe000) {  // 1110 ????  ???? ????
			uint16_t inst2 = memory->readHalfWord(pc() + 2);
			uint16_t inst3 = memory->readHalfWord(pc() + 4);
			scalar48(inst1, inst2, inst3);
		} else if ((inst1 & 0xf800) == 0xf000) {  // 1111 0???  ???? ????
			uint16_t inst2 = memory->readHalfWord(pc() + 2);
			uint16_t inst3 = memory->readHalfWord(pc() + 4);
			vector48(inst1, inst2, inst3);
		} else if ((inst1 & 0xf800) == 0xf800) {  // 1111 1???  ???? ????
			uint32_t inst2 = memory->readHalfWord(pc() + 2);
			inst2 = (inst2 << 16) | memory->readHalfWord(pc() + 4);
			uint32_t inst3 = memory->readHalfWord(pc() + 6);
			inst3 = (inst3 << 16) | memory->readHalfWord(pc() + 8);
			vector80(inst1, inst2, inst3);
		} else {
			log->error("vc4", "Unsupported instruction: 0x%04x", inst1);
			throw std::runtime_error("Unsupported instruction decode.");
		}
		log->incrementTime();
	}

	void scalar16(uint16_t inst) {
		log->debug("vc4", "scalar16: 0x%04x", inst);
		if (inst == 0x0000) {
			// TODO: HALT?
		} else if (inst == 0x0001) {
			// NOP
		} else if (inst == 0x0004) {
			execute.unk0004();
			// TODO
		} else if (inst == 0x0005) {
			execute.unk0005();
			// TODO
		} else if (inst == 0x000a) {
			execute.rti();
		} else if ((inst & 0xffe0) == 0x0040) {
			execute.b(inst & 0x1f);
			return;
		} else if ((inst & 0xffe0) == 0x0060) {
			execute.bl(inst & 0x1f, 2);
			return;
		} else if ((inst & 0xfff0) == 0x0080) {
			return execute.switchb(inst & 0x1f);
		} else if ((inst & 0xffe0) == 0x00a0) {
			return execute.switch16(inst & 0x1f);
		} else if ((inst & 0xffe0) == 0x00e0) {
			execute.cpuid(inst & 0x1f);
		/*} else if ((inst & 0xf800) == 0x5000) {
			unsigned int shift = (inst >> 9) & 0x3;
			unsigned int rs = (inst >> 4) & 0x1f;
			unsigned int rd = inst & 0xf;
			execute.add(rd, rs, shift);
		*/} else if ((inst & 0xe000) == 0x4000) {
			unsigned int op = (inst >> 8) & 0x1f;
			unsigned int rs = (inst >> 4) & 0xf;
			unsigned int rd = inst & 0xf;
			execute.binaryOp(op, rd, rs);
		} else if ((inst & 0xe000) == 0x6000) {
			unsigned int op = (inst >> 9) & 0xf;
			unsigned int imm5 = (inst >> 4) & 0x1f;
			unsigned int rd = inst & 0xf;
			execute.binaryOpImm(op << 1, rd, imm5);
		} else if ((inst & 0xf800) == 0x1800) {
			unsigned int cond = (inst >> 7) & 0xf;
			int offset = inst & 0x7F;
			offset = extendSigned(offset, 0x40);
			offset *= 2;
			if (execute.bcc(cond, offset)) {
				return;
			}
		} else if ((inst & 0xf800) == 0x1000) {
			int32_t offset = (inst >> 5) & 0x3f;
			if ((offset & 0x20) != 0) {
				offset |= 0xffffffc0;
			}
			offset *= 4;
			unsigned int rd = inst & 0x1f;
			execute.leaSp(rd, offset);
		} else if ((inst & 0xfe00) == 0x0200) {
			// push/pop
			bool push = (inst & 0x80) != 0;
			bool lrpc = (inst & 0x100) != 0;
			unsigned int bank = (inst >> 5) & 0x3;
			unsigned int start = bank * 8;
			if (bank == 1) {
				start = 6;
			}
			unsigned int count = (inst & 0x1f) + 1;
			execute.pushPop(push, lrpc, start, count);
			if (!push && (lrpc || VC_PC < start + count)) {
				return;
			}
		} else if ((inst & 0xfc00) == 0x0400) {
			bool store = (inst & 0x0200) != 0;
			unsigned int rd = inst & 0xf;
			int32_t offset = (inst >> 4) & 0x1f;
			offset = extendSigned(offset, 0x10);
			offset *= 4;
			execute.loadStoreOffset(store, WIDTH_U32, rd, VC_SP, offset);
		} else if ((inst & 0xf800) == 0x0800) {
			bool store = (inst & 0x0100) != 0;
			unsigned int format = (inst >> 9) & 0x3;
			unsigned int rd = inst & 0xf;
			unsigned int rs = (inst >> 4) & 0xf;
			execute.loadStoreOffset(store, format, rd, rs, 0);
		} else if ((inst & 0xe000) == 0x2000) {
			bool store = (inst & 0x1000) != 0;
			unsigned int rd = inst & 0xf;
			unsigned int rs = (inst >> 4) & 0xf;
			// TODO: Signed offset?
			unsigned int offset = (inst >> 8) & 0xf;
			execute.loadStoreOffset(store, WIDTH_U32, rd, rs, offset * 4);
		} else {
			// TODO
			throw std::runtime_error("scalar16: Unsupported instruction.");
		}
		registers.setRegister(VC_PC, pc() + 2);
	}

	void scalar32(uint16_t inst1, uint16_t inst2) {
		log->debug("vc4", "scalar32: 0x%04x 0x%04x", inst1, inst2);
		if ((inst1 & 0xf080) == 0x9000) {                                       // 1001 ????  0??? ????
			unsigned int cond = (inst1 >> 8) & 0xf;
			int32_t offset = (uint32_t)inst2 | ((uint32_t)(inst1 & 0x7f) << 16);
			offset = extendSigned(offset, 0x0400000) * 2;
			log->debug("vc4", "cond: %08x", cond);
			log->debug("vc4", "offset: %08x", offset);
			if (execute.bcc(cond, offset)) {
				return;
			}
		} else if ((inst1 & 0xf080) == 0x9080) {                                // 1001 ????  1??? ????
			int32_t offset = (uint32_t)inst2 | ((uint32_t)(inst1 & 0x7f) << 16);
			log->debug("vc4", "offset: %08x", offset);
			offset |= (uint32_t)(inst1 & 0xf00) << 15;
			log->debug("vc4", "offset: %08x", offset);
			offset = extendSigned(offset, 0x04000000);
			log->debug("vc4", "offset: %08x", offset);
			execute.blImm(offset * 2, 4);
			return;
		} else if ((inst1 & 0xfc00) == 0xc000 && (inst2 & 0x0060) == 0x0000) {  // 1100 00??  ???? ????   ???? ????  ?00? ????
			unsigned int op = (inst1 >> 5) & 0x1f;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int rb = inst2 & 0x1f;
			unsigned int cond = (inst2 >> 7) & 0xf;
			execute.binaryOp(cond, op, rd, ra, rb);
		} else if ((inst1 & 0xfc00) == 0xc000 && (inst2 & 0x0040) == 0x0040) {  // 1100 00??  ???? ????   ???? ????  ?1?? ????
			unsigned int op = (inst1 >> 5) & 0x1f;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			int32_t imm = inst2 & 0x3f;
			imm = extendSigned(imm, 0x20);
			unsigned int cond = (inst2 >> 7) & 0xf;
			execute.binaryOpImm(cond, op, rd, ra, imm);
		} else if ((inst1 & 0xfc00) == 0xa800) {                                // 1010 10??  ???? ????
			bool store = (inst1 & 0x20) != 0;
			static const unsigned int BASE_REG[] = {
				24, VC_SP, VC_PC, 0
			};
			unsigned int rb = BASE_REG[(inst1 >> 8) & 0x3];
			unsigned int format = (inst1 >> 6) & 0x3;
			unsigned int rd = inst1 & 0x1f;
			execute.loadStoreOffset(store, format, rd, rb,
					extendSigned(inst2, 0x8000));
		} else if ((inst1 & 0xff00) == 0xa000 && (inst2 & 0x0060) == 0x0000) {  // 1010 0000  ???? ????   ???? ????  ?00? ????
			bool store = (inst1 & 0x20) != 0;
			unsigned int format = (inst1 >> 6) & 0x3;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int rb = inst2 & 0x1f;
			unsigned int cond = (inst2 >> 7) & 0xf;
			execute.loadStoreIndexed(store, format, rd, ra, rb, cond);
		} else if ((inst1 & 0xfe00) == 0xa200) {                                // 1010 001?  ???? ????
			bool store = (inst1 & 0x20) != 0;
			unsigned int rd = inst1 & 0x1f;
			unsigned int rs = inst2 >> 11;
			int offset = inst2 & 0x7ff;
			offset |= (inst1 << 3) & 0x800;
			offset = extendSigned(offset, 0x800);
			unsigned int format = (inst1 >> 6) & 0x3;
			// TODO: Offset scale?
			execute.loadStoreOffset(store, format, rd, rs, offset);
		} else if ((inst1 & 0xfe00) == 0xa400) {
			bool store = (inst1 & 0x20) != 0;
			unsigned int rd = inst1 & 0x1f;
			unsigned int rs = inst2 >> 11;
			unsigned int format = (inst1 >> 6) & 0x3;
			unsigned int cond = (inst2 >> 7) & 0xf;
			bool postincrement = (inst1 & 0x100) != 0;
			bool predecrement = !postincrement;
			execute.loadStoreOffset(store, format, rd, rs, 0, cond,
					postincrement, predecrement);
		} else if ((inst1 & 0xfc00) == 0xb000) {
			unsigned int op = (inst1 >> 5) & 0x1f;
			unsigned int rd = inst1 & 0x1f;
			unsigned int imm = extendSigned(inst2, 0x8000); // FIXME
			execute.binaryOpImm(14, op, rd, rd, imm);
		} else if ((inst1 & 0xfc00) == 0xb400) {
			unsigned int rd = inst1 & 0x1f;
			unsigned int rs = (inst1 >> 5) & 0x1f;
			int32_t offset = (int16_t)inst2;
			execute.binaryOpImm(14, OP_ADD, rd, rs, offset);
		} else if ((inst1 & 0xffe0) == 0xbfe0) {
			unsigned int rd = inst1 & 0x1f;
			int32_t offset = (int16_t)inst2;
			execute.binaryOpImm(14, OP_ADD, rd, 31, offset);
		} else if ((inst1 & 0xf000) == 0x8000) {
			unsigned int cond = (inst1 >> 8) & 0xf;
			unsigned int rd = inst1 & 0xf;
			bool compareImmediate = (inst2 & 0x8000) != 0;
			bool addImmediate = (inst2 & 0x4000) != 0;
			if (addImmediate) {
				int32_t imm = (inst1 >> 4) & 0xf;
				imm = extendSigned(imm, 0x8);
				execute.binaryOpImm(OP_ADD, rd, imm);
			} else {
				execute.binaryOp(OP_ADD, rd, (inst1 >> 4) & 0xf);
			}
			int32_t offset;
			if (compareImmediate) {
				offset = extendSigned(inst2 & 0xff, 0x80) * 2;
				// TODO: Signed imm?
				unsigned int imm = (inst2 >> 8) & 0x3f;
				if (execute.bccCmpImm(cond, rd, imm, offset)) {
					return;
				}
				// TODO
			} else {
				offset = extendSigned(inst2 & 0x3ff, 0x200) * 2;
				unsigned int rs = (inst2 >> 10) & 0xf;
				if (execute.bccCmp(cond, rd, rs, offset)) {
					return;
				}
			}
		} else if ((inst1 & 0xff80) == 0xc480 && (inst2 & 0x20) == 0) {         // 1100 0100  1??? ????   ???? ????  ??0? ????
			unsigned int cond = (inst2 >> 7) & 0xf;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int rb = inst2 & 0x1f;
			bool aUnsigned = (inst1 & 0x40) != 0;
			bool bUnsigned = (inst1 & 0x20) != 0;
			bool immediate = (inst2 & 0x40) != 0;
			if (immediate) {
				// TODO
				throw std::runtime_error("div with immediate unimplemented!");
			} else {
				execute.div(cond, rd, ra, rb, aUnsigned, bUnsigned);
			}
			// TODO
		} else if ((inst1 & 0xffe0) == 0xc5e0 && (inst2 & 0x60) == 0x0) {       // 1100 0101  111d dddd   aaaa accc  c00b bbbb
			unsigned int cond = (inst2 >> 7) & 0xf;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int rb = inst2 & 0x1f;
			// TODO: ?
			execute.addShl(cond, rd, ra, rb, 8);
		} else if ((inst1 & 0xff80) == 0xca00 && (inst2 & 0x40) == 0x40) {      // 1100 1010  0ood dddd   aaaa accc  c1?? ????
			unsigned int cond = (inst2 >> 7) & 0xf;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int op = (inst1 >> 5) & 0x3;
			int shift = extendSigned(inst2 & 0x3f, 0x20);
			execute.floatConv(cond, (FloatConvOp)op, rd, ra, shift);
		} else if ((inst1 & 0xfe00) == 0xc800 && (inst2 & 0x60) == 0x0) {       // 1100 100o  oood dddd   aaaa accc  c00b bbbb
			unsigned int cond = (inst2 >> 7) & 0xf;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int op = (inst1 >> 5) & 0xf;
			unsigned int rb = inst2 & 0x1f;
			execute.floatOp(cond, (FloatOp)op, rd, ra, rb);
		} else if ((inst1 & 0xfe00) == 0xc800 && (inst2 & 0x40) == 0x40) {      // 1100 100o  oood dddd   aaaa accc  c1ii iiii
			unsigned int cond = (inst2 >> 7) & 0xf;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int op = (inst1 >> 5) & 0xf;
			int32_t imm = extendSigned(inst2 & 0x3f, 0x40);
			execute.floatOpImm(cond, (FloatOp)op, rd, ra, imm);
		} else if ((inst1 & 0xff80) == 0xc400 && (inst2 & 0x60) == 0x0) {       // 1100 0100  0ssd dddd   aaaa accc  c00b bbbb
			unsigned int cond = (inst2 >> 7) & 0xf;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int rb = inst2 & 0x1f;
			bool aUnsigned = (inst1 & 0x0040) != 0;
			bool bUnsigned = (inst1 & 0x0020) != 0;
			execute.mulhd(cond, rd, ra, rb, aUnsigned, bUnsigned);
                } else if ((inst1 & 0xffe0) == 0xc580 && (inst2 & 0x70) == 0x50) {    // 1100 0101  100d dddd   aaaa accc  c101 iiii
                        unsigned int cond = (inst2 >> 7) & 0xf;
                        unsigned int rd = inst1 & 0x1f;
                        unsigned int ra = (inst2 >> 11) & 0x1f;
                        uint32_t imm = 0x200 | ((inst2 & 0xf) << 5);
                        execute.binaryOpImm(cond, OP_ADD, rd, ra, imm);
		} else {
			// TODO
			throw std::runtime_error("scalar32: Unsupported instruction.");
		}
		registers.setRegister(VC_PC, pc() + 4);
	}

	void scalar48(uint16_t inst1, uint16_t inst2, uint16_t inst3) {
		log->debug("vc4", "scalar48: 0x%04x 0x%04x 0x%04x", inst1, inst2,
				inst3);
		if ((inst1 & 0xfc00) == 0xe800) {
			unsigned int op = (inst1 >> 5) & 0x1f;
			unsigned int rd = inst1 & 0x1f;
			unsigned int imm = inst3;
			imm = (imm << 16) | inst2;
			execute.binaryOpImm(op, rd, imm);
		} else if ((inst1 & 0xffe0) == 0xe500) {
			unsigned int rd = inst1 & 0x1f;
			unsigned int imm = inst3;
			imm = (imm << 16) | inst2;
			execute.leaPc(rd, imm);
		} else if ((inst1 & 0xff00) == 0xe600) {
			bool store = (inst1 & 0x20) != 0;
			unsigned int format = (inst1 >> 6) & 0x3;
			unsigned int rd = inst1 & 0x1f;
			unsigned int rs = inst3 >> 11;
			int offset = inst3 & 0x7ff;
			offset = (offset << 16) | inst2;
			offset = extendSigned(offset, 0x4000000);
			log->debug("vc4", "offset: %08x", offset);
			execute.loadStoreOffset(store, format, rd, rs, offset);
                } else if ((inst1 & 0xff00) == 0xe700) {
                        bool store = (inst1 & 0x20) != 0;
                        unsigned int format = (inst1 >> 6) & 0x3;
                        unsigned int rd = inst1 & 0x1f;
                        unsigned int rs = inst3 >> 11;
                        int offset = inst3 & 0x7ff;
                        offset = (offset << 16) | inst2;
                        offset = extendSigned(offset, 0x4000000);
                        execute.loadStoreOffset(store, format, rd, rs, offset);
		} else if ((inst1 & 0xfc00) == 0xec00) {
			unsigned int rs = (inst1 >> 5) & 0x1f;
			unsigned int rd = inst1 & 0x1f;
			unsigned int imm = inst3;
			imm = (imm << 16) | inst2;
			execute.binaryOpImm(14, OP_ADD, rd, rs, imm);
		} else {
			throw std::runtime_error("scalar48: Unsupported instruction.");
			// TODO
		}
		registers.setRegister(VC_PC, pc() + 6);
	}

	void vector48(uint16_t inst1, uint16_t inst2, uint16_t inst3) {
		// TODO
		throw std::runtime_error("vector48: Unsupported instruction.");
		registers.setRegister(VC_PC, pc() + 6);
	}

	void vector80(uint16_t inst1, uint32_t inst2, uint32_t inst3) {
		// TODO
                if ( (inst1 == 0xfe03) && (inst2 == 0xc0380400) && (inst3 == 0xfbc00000) ) {
                  printf("v32mov HY(0++,0),0 REP8\n");
                  for (int row = 0; row < 8; row++) {
                    for (int col = 0; col < 16; col++) {
                      vector_file.write32(row, col, 0);
                    }
                  }
                } else if ( (inst1 == 0xf893) && (inst2 == 0xe0300380) && (inst3 == 0x43e00014) ) {
                  //printf("v32st HY(0++,0),(r5+=r4) REP8\n");
                  // write 16 uint32_t's to r5, increment r5 by r4, repeat 8 times
                  // r5 is the destination address to start at
                  // r4 is how much to increment r5 by, after each SIMD row
                  // increments to r5 dont actually persist within the real r5
                  uint32_t stride = registers.getRegister(4);
                  uint32_t target = registers.getRegister(5);
                  for (int row=0; row<8; row++) {
                    uint32_t row_target = target + (row * stride);
                    for (int col=0; col<16; col++) {
                      memory->writeWord(row_target + (col * 4), vector_file.read32(row, col));
                    }
                  }
                } else {
                  printf("vector80 0x%04x 0x%08x 0x%08x\n", inst1, inst2, inst3);
		  throw std::runtime_error("vector80: Unsupported instruction.");
                }
		registers.setRegister(VC_PC, pc() + 10);
	}
private:
	uint32_t pc() {
		return registers.getRegister(VC_PC);
	}

	Memory *memory;
	VideoCoreIVRegisterFile &registers;
        VectorFile &vector_file;
	Log *log;

	VideoCoreIVExecute execute;
};

#endif
