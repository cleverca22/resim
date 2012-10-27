
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
	                  Log *log)
			: memory(memory), registers(registers), log(log),
			execute(memory, registers, log) {
	}

	void step() {
		log->debug("vc4", "pc: %08x", pc());
		uint16_t inst1 = memory->readHalfWord(pc());
		if ((inst1 & 0x8000) == 0) {
			scalar16(inst1);
		} else if ((inst1 & 0xc000) == 0x8000) {
			uint16_t inst2 = memory->readHalfWord(pc() + 2);
			scalar32(inst1, inst2);
		} else if ((inst1 & 0xe000) == 0xc000) {
			uint16_t inst2 = memory->readHalfWord(pc() + 2);
			scalar32(inst1, inst2);
		} else if ((inst1 & 0xf000) == 0xe000) {
			uint16_t inst2 = memory->readHalfWord(pc() + 2);
			uint16_t inst3 = memory->readHalfWord(pc() + 4);
			scalar48(inst1, inst2, inst3);
		} else if ((inst1 & 0xf800) == 0xf000) {
			uint16_t inst2 = memory->readHalfWord(pc() + 2);
			uint16_t inst3 = memory->readHalfWord(pc() + 4);
			vector48(inst1, inst2, inst3);
		} else if ((inst1 & 0xf800) == 0xf800) {
			uint32_t inst2 = memory->readWord(pc() + 2);
			uint32_t inst3 = memory->readWord(pc() + 6);
			vector80(inst1, inst2, inst3);
		} else {
			log->error("vc4", "Unsupported instruction: 0x%04x", inst1);
			throw std::runtime_error("Unsupported instruction.");
		}
	}

	void scalar16(uint16_t inst) {
		log->debug("vc4", "scalar16: 0x%04x", inst);
		if (inst == 0x0000) {
			// TODO: HALT?
		} else if (inst == 0x0001) {
			// NOP
		} else if (inst == 0x000a) {
			execute.rti();
		} else if ((inst & 0xffe0) == 0x0040) {
			execute.b(inst & 0x1f);
		} else if ((inst & 0xffe0) == 0x0060) {
			execute.bl(inst & 0x1f);
		} else if ((inst & 0xffe0) == 0x0080) {
			execute.tbb(inst & 0x1f);
		} else if ((inst & 0xffe0) == 0x00a0) {
			execute.tbh(inst & 0x1f);
		} else if ((inst & 0xffe0) == 0x00e0) {
			execute.cpuid(inst & 0x1f);
		} else if ((inst & 0xf800) == 0x5000) {
			unsigned int shift = (inst >> 9) & 0x3;
			unsigned int rs = (inst >> 4) & 0x1f;
			unsigned int rd = inst & 0xf;
			execute.add(rd, rs, shift);
		} else if ((inst & 0xe000) == 0x4000) {
			unsigned int op = (inst >> 8) & 0x1f;
			unsigned int rs = (inst >> 4) & 0xf;
			unsigned int rd = inst & 0xf;
			// TODO: op rd, rs
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
		} else if ((inst & 0xe000) == 0x2000) {
			bool store = (inst & 0x1000) != 0;
			unsigned int rd = inst & 0xf;
			unsigned int rs = (inst >> 4) & 0xf;
			// TODO: Signed offset?
			unsigned int offset = (inst >> 8) & 0xf;
			execute.loadStoreOffset(store, WIDTH_U32, rd, rs, offset * 4);
		} else {
			// TODO
			throw std::runtime_error("Unsupported instruction.");
		}
		registers.setRegister(VC_PC, pc() + 2);
	}

	void scalar32(uint16_t inst1, uint16_t inst2) {
		log->debug("vc4", "scalar32: 0x%04x 0x%04x", inst1, inst2);
		if ((inst1 & 0xf080) == 0x9080) {
			int32_t offset = (uint32_t)inst2 | ((uint32_t)(inst1 & 0x7f) << 16);
			log->debug("vc4", "offset: %08x", offset);
			offset |=  (uint32_t)(inst1 & 0xf00) << 15;
			log->debug("vc4", "offset: %08x", offset);
			offset = extendSigned(offset, 0x04000000);
			log->debug("vc4", "offset: %08x", offset);
			execute.blImm(offset * 2, 4);
			return;
		} else if ((inst1 & 0xfc00) == 0xc000 && (inst2 & 0x0060) == 0x0000) {
			unsigned int op = (inst1 >> 5) & 0x1f;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int rb = inst2 & 0x1f;
			unsigned int cond = (inst2 >> 7) & 0xf;
			execute.binaryOp(cond, op, rd, ra, rb);
		} else if ((inst1 & 0xfc00) == 0xc000 && (inst2 & 0x0040) == 0x0040) {
			unsigned int op = (inst1 >> 5) & 0x1f;
			unsigned int rd = inst1 & 0x1f;
			unsigned int ra = (inst2 >> 11) & 0x1f;
			unsigned int imm = inst2 & 0x3f;
			unsigned int cond = (inst2 >> 7) & 0xf;
			execute.binaryOpImm(cond, op, rd, ra, imm);
		} else if ((inst1 & 0xfc00) == 0xa800) {
			bool store = (inst1 & 0x20) != 0;
			static const unsigned int BASE_REG[] = {
				24, VC_SP, VC_PC, 0
			};
			unsigned int rb = BASE_REG[(inst1 >> 8) & 0x3];
			unsigned int format = (inst1 >> 6) & 0x3;
			unsigned int rd = inst1 & 0x1f;
			execute.loadStoreOffset(store, format, rd, rb, inst2);
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
		} else {
			// TODO
			throw std::runtime_error("Unsupported instruction.");
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
		} else {
			throw std::runtime_error("Unsupported instruction.");
			// TODO
		}
		registers.setRegister(VC_PC, pc() + 6);
	}

	void vector48(uint16_t inst1, uint16_t inst2, uint16_t inst3) {
		// TODO
		throw std::runtime_error("Unsupported instruction.");
		registers.setRegister(VC_PC, pc() + 6);
	}

	void vector80(uint16_t inst1, uint32_t inst2, uint32_t inst3) {
		// TODO
		throw std::runtime_error("Unsupported instruction.");
		registers.setRegister(VC_PC, pc() + 10);
	}
private:
	uint32_t pc() {
		return registers.getRegister(VC_PC);
	}

	Memory *memory;
	VideoCoreIVRegisterFile &registers;
	Log *log;

	VideoCoreIVExecute execute;
};

#endif