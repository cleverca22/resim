
#ifndef RESIM_VIDEOCOREIVEXECUTE_HPP_INCLUDED
#define RESIM_VIDEOCOREIVEXECUTE_HPP_INCLUDED

#include "Log.hpp"
#include "Memory.hpp"
#include "videocore/VideoCoreIVRegisterFile.hpp"

#include <stdexcept>
#include <cassert>
#include <math.h>
#include <set>
#include <string.h>

static const uint32_t VIDEOCORE4_CPUID = 0x04000104;

enum BinaryOp {
	OP_MOV, // 0
	OP_CMN,
	OP_ADD,
	OP_BIC,
	OP_MUL,
	OP_EOR, // 5
	OP_SUB,
	OP_AND,
	OP_MVN,
	OP_ROR,
	OP_CMP, // 10
	OP_RSB,
	OP_BTST,
	OP_OR,
	OP_EXTU,
	OP_MAX, // 15
	OP_BSET,
	OP_MIN,
	OP_BCLR,
	OP_ADDS2,
	OP_BITFLIP, // 20
	OP_ADDS4,
	OP_ADDS8,
	OP_ADDS16,
	OP_EXTS,
	OP_NEG, // 25
	OP_LSR,
	OP_CLZ,
	OP_LSL,
	OP_BREV,
	OP_ASR, // 30
	OP_ABS, // 31
	OP_MULHD_SS,
	OP_MULHD_SU,
	OP_MULHD_US,
	OP_MULHD_UU, // 35
	OP_DIV_SS,
	OP_DIV_SU,
	OP_DIV_US,
	OP_DIV_UU,
	OP_ADDS,
	OP_SUBS,
	OP_SHLS,
	OP_CLIPSH,
	OP_ADDSCALE_5,
	OP_ADDSCALE_6,
	OP_ADDSCALE_7,
	OP_ADDSCALE_8,
	OP_COUNT,
	OP_SUBSCALE_1,
	OP_SUBSCALE_2,
	OP_SUBSCALE_3,
	OP_SUBSCALE_4,
	OP_SUBSCALE_5,
	OP_SUBSCALE_6,
	OP_SUBSCALE_7,
	OP_SUBSCALE_8
};

enum LoadStoreWidth {
	WIDTH_U32,
	WIDTH_U16,
	WIDTH_U8,
	WIDTH_S16
};

enum FloatConvOp {
	OP_FTRUNC,
	OP_FLOOR,
	OP_FLTS,
	OP_FLTU
};

enum FloatOp {
	OP_FADD,
	OP_FSUB,
	OP_FMUL,
	OP_FDIV,
	OP_FCMP,
	OP_FABS,
	OP_FRSB,
	OP_FMAX,
	OP_RRCP,
	OP_FRSQRT,
	OP_FNMUL,
	OP_FMIN,
	OP_FLD1,
	OP_FLD0,
	OP_FOP14,
	OP_FOP15
};

enum Condition {
	COND_EQ,
	//COND_NE,
	COND_CS,
	//COND_CC,
	COND_NS,
	//COND_NC,
	COND_VS,
	//COND_VC,
	COND_HI,
	//COND_LS,
	COND_GE,
	//COND_LT,
	COND_GT,
	//COND_LE,
	COND_TRUE,
	//COND_FALSE
};

static unsigned int loadStoreSize(LoadStoreWidth format) {
	switch (format) {
		case WIDTH_U32:
			return 4;
		case WIDTH_U16:
		case WIDTH_S16:
			return 2;
		case WIDTH_U8:
			return 1;
		default:
			assert(false && "Invalid format!");
	}
}

union floatbits {
  float f;
  uint32_t u;
};

const char *funcToName(uint32_t addr) {
  static char buffer[10];
  switch (addr) {
  case 0x60000ef2: return "delay_thing2";
  case 0x60000166: return "thing4";
  case 0x6000023c: return "bzero_l2_cache";
  case 0x600003e8: return "delay_thing";
  case 0x600026f8: return "thing1";
  case 0x60002cc0: return "otp_thing";
  case 0x60003456: return "busy_delay";
  default:
    snprintf(buffer, 10, "%08x", addr);
    return buffer;
  }
}

class Analyzer {
public:
  Analyzer() {
    FILE *fd = fopen("entry-points.txt", "r");
    while (!feof(fd)) {
      uint32_t addr;
      int i = fscanf(fd, "%x\n", &addr);
      entrypoints.insert(addr);
    }
    fclose(fd);
    this->fd = fopen("entry-points.txt", "w+");
    callgraph = fopen("call-graph.dot", "w");
  }
  void record_entry(uint32_t currentpc, uint32_t addr, VideoCoreIVRegisterFile &registers) {
    fprintf(fd, "%08x\n", addr);
    fflush(fd);
    uint32_t func_start = 0;
    for (auto it = entrypoints.begin(); it != entrypoints.end(); ++it) {
      uint32_t maybe = *it;
      if (currentpc > maybe) func_start = maybe;
      else if (currentpc < maybe) break;
    }
    char name1[64], name2[64];
    strncpy(name1, funcToName(func_start), 64);
    strncpy(name2, funcToName(addr), 64);
    printf("%s+0x%x called %s\t", name1, currentpc - func_start, name2);
    printf("R0 = 0x%08x ", registers.getRegister(0));
    printf("R1 = 0x%08x ", registers.getRegister(1));
    printf("R2 = 0x%08x\n", registers.getRegister(2));
    fprintf(callgraph, "\"0x%x\" -> \"0x%x\"\n", func_start, addr);
    fflush(callgraph);
  }
private:
  std::set<uint32_t> entrypoints;
  FILE *fd;
  FILE *callgraph;
};

extern Analyzer analyzer;

class VideoCoreIVExecute {
public:
	VideoCoreIVExecute(Memory *memory,
	                   VideoCoreIVRegisterFile &registers,
	                   Log *log)
			: memory(memory), registers(registers), log(log) {
	}

	void rti() {
		// TODO
		throw std::runtime_error("Unsupported instruction1.");
	}

	void b(unsigned int reg) {
		registers.setRegister(VC_PC, registers.getRegister(reg));
	}

  void bl(unsigned int reg, unsigned int instSize) {
    uint32_t oldpc = registers.getRegister(VC_PC);
    registers.setRegister(VC_LR, registers.getRegister(VC_PC) + instSize);
    registers.setRegister(VC_PC, registers.getRegister(reg));
    uint32_t newpc = registers.getRegister(reg);
    //printf("\"0x%08lx\" -> \"0x%08lx\"\n", oldpc, newpc);
    analyzer.record_entry(oldpc, newpc, registers);
  }

  void blImm(int32_t offset, uint32_t instSize) {
    uint32_t pc = registers.getRegister(VC_PC);
    log->debug("vc4exec", "blImm: lr=%08x", pc + instSize);
    registers.setRegister(VC_LR, pc + instSize);
    registers.setRegister(VC_PC, pc + offset);
    uint32_t newpc = registers.getRegister(VC_PC);
    analyzer.record_entry(pc, newpc, registers);
    //printf("\"0x%08lx\" -> \"0x%08lx\"\n", pc, newpc);
  }

  void switchb(unsigned int reg) {
    uint32_t table_addr = registers.getRegister(VC_PC) + 2;
    uint32_t new_pc = table_addr + (memory->readByte(table_addr + registers.getRegister(reg)) * 2);
    registers.setRegister(VC_PC, new_pc);
  }

  void switch16(unsigned int reg) {
    uint32_t table_addr = registers.getRegister(VC_PC) + 2;
    uint32_t new_pc = table_addr + (memory->readHalfWord(table_addr + (registers.getRegister(reg)*2)) * 2);
    registers.setRegister(VC_PC, new_pc);
  }

	void cpuid(unsigned int reg) {
		registers.setRegister(reg, VIDEOCORE4_CPUID);
	}

	void addShl(unsigned int cond, unsigned int rd, unsigned int ra, unsigned int rb, unsigned int shift) {
		log->debug("vc4exec", "addShl");
		if (!checkCond(cond)) {
			return;
		}
		uint32_t a = registers.getRegister(ra);
		uint32_t b = registers.getRegister(rb) << shift;
		registers.setRegister(rd, a + b);
	}

	void binaryOp(unsigned int op, unsigned int rd, unsigned int rs) {
		uint32_t a = registers.getRegister(rd);
		uint32_t b = registers.getRegister(rs);
		doBinaryOp(op, rd, a, b);
	}

	void binaryOpImm(unsigned int op, unsigned int rd, int32_t imm) {
		uint32_t a = registers.getRegister(rd);
		doBinaryOp(op, rd, a, imm);
	}

	void binaryOp(unsigned int cond, unsigned int op, int rd, int ra, int rb) {
		if (!checkCond(cond)) {
			return;
		}
		uint32_t a = registers.getRegister(ra);
		uint32_t b = registers.getRegister(rb);
		doBinaryOp(op, rd, a, b);
	}

	void binaryOpImm(int cond, int op, int rd, int ra, int imm) {
		if (!checkCond(cond)) {
			return;
		}
		uint32_t a = registers.getRegister(ra);
		doBinaryOp(op, rd, a, imm);
	}

	bool bcc(unsigned int cond, int32_t offset) {
		if (!checkCond(cond)) {
			return false;
		}
		registers.setRegister(VC_PC, registers.getRegister(VC_PC) + offset);
		return true;
	}

	bool bccCmp(unsigned int cond, int rd, int rs, int32_t offset) {
		uint32_t b = registers.getRegister(rs);
		log->debug("vc4exec", "bccCmp %d %d %d", cond, rd, rs);
		return bccCmpImm(cond, rd, b, offset);
	}

	bool bccCmpImm(unsigned int cond, int rd, uint32_t imm, int32_t offset) {
		uint32_t a = registers.getRegister(rd);
		log->debug("vc4exec", "bccCmpImm: %d %08x %08x", cond, a, imm);
		unsigned int status = compare(a, imm);
		if (!checkCond(cond, status)) {
			return false;
		}
		registers.setRegister(VC_PC, registers.getRegister(VC_PC) + offset);
		return true;
	}

	void pushPop(bool push, bool lrpc, unsigned int start, unsigned int count) {
		if (push) {
			if (lrpc) {
				this->push(VC_LR);
			}
			if (lrpc && (((count - 1) & 0xf) == 0xf)) {
				// Special case, only maybe push the first register
				if ((count - 1) == 0x1f) {
					this->push(start);
				}
			} else {
				for (unsigned int i = 0; i < count; i++) {
					this->push((start + i) % 32);
				}
			}
		} else {
			if (lrpc && (((count - 1) & 0xf) == 0xf)) {
				// Special case, only maybe pop the first register
				if ((count - 1) == 0x1f) {
					this->pop(start);
				}
			} else {
				for (int i = count - 1; i >= 0; i--) {
					this->pop((start + i) % 32);
				}
			}
			if (lrpc) {
				this->pop(VC_PC);
			}
		}
	}

	void push(unsigned int reg) {
		uint32_t sp = registers.getRegister(VC_SP);
		sp -= 4;
		uint32_t value = registers.getRegister(reg);
		log->debug("vc4exec", "pushing %d to %08x: %08x", reg, sp, value);
		memory->writeWord(sp, registers.getRegister(reg));
		registers.setRegister(VC_SP, sp);
	}

	void pop(unsigned int reg) {
		uint32_t sp = registers.getRegister(VC_SP);
		log->debug("vc4exec", "popping %d to %08x: %08x", reg, sp, memory->readWord(sp));
		registers.setRegister(reg, memory->readWord(sp));
		sp += 4;
		registers.setRegister(VC_SP, sp);
	}

	void loadStoreOffset(bool store, int format, int rd, int rb, int offset,
			unsigned int cond = 14, bool postincrement = false,
			bool predecrement = false) {
		if (!checkCond(cond)) {
			return;
		}
		unsigned int size = loadStoreSize((LoadStoreWidth)format);
		if (predecrement) {
			registers.setRegister(rb, registers.getRegister(rb) - size);
		}
		uint32_t address = registers.getRegister(rb) + offset;
		doLoadStore(store, format, rd, address);
		if (postincrement) {
			registers.setRegister(rb, registers.getRegister(rb) + size);
		}
	}

	void loadStoreIndexed(bool store, int format, int rd, int ra, int rb,
			unsigned int cond = 14) {
		if (!checkCond(cond)) {
			return;
		}
		uint32_t offset = registers.getRegister(rb) * loadStoreSize((LoadStoreWidth)format);
		uint32_t address = offset + registers.getRegister(ra);
		doLoadStore(store, format, rd, address);
	}

	void leaSp(unsigned int rd, int32_t offset) {
		uint32_t address = registers.getRegister(VC_SP) + offset;
		registers.setRegister(rd, address);
	}

	void leaPc(unsigned int rd, int32_t offset) {
		uint32_t address = registers.getRegister(VC_PC) + offset;
		registers.setRegister(rd, address);
	}

	void floatConv(unsigned int cond, FloatConvOp op, int rd, int ra, int shift) {
		if (!checkCond(cond)) {
			return;
		}
                floatbits valfb;
                valfb.u = registers.getRegister(ra);
		switch (op) {
			case OP_FLOOR:
				valfb.f = floorf(valfb.f);
				break;
			case OP_FTRUNC:
				valfb.u = (int32_t) valfb.f;
				break;
			case OP_FLTS:
				valfb.f = (int32_t) valfb.u;
				break;
			case OP_FLTU:
				valfb.f = valfb.u;
				break;
		}
		switch (op) {
			case OP_FLOOR:
			case OP_FTRUNC: {
				if (shift > 0) {
					valfb.u <<= shift;
				} else {
					valfb.u >>= -shift;
				}
				break;
			}
			case OP_FLTS:
			case OP_FLTU:
				log->debug("vc4exec", "shift %f >> %d",
                                           valfb.f, shift);
				int32_t exponent = (valfb.u >> 23) & 0xff;
				assert(exponent - shift < 0x100
                                       && exponent - shift >= 0);
				exponent = exponent - shift;
				valfb.u = (valfb.u & 0x807fffff)
                                          | (exponent << 23);
				log->debug("vc4exec", "result %f", valfb.f);
				break;
		}
		log->debug("vc4exec", "floatConv, result %08x/%d/%f", valfb.u,
                           valfb.u, valfb.f);
		registers.setRegister(rd, valfb.u);
	}

	void floatOp(unsigned int cond, FloatOp op, int rd, int ra, int rb) {
		if (!checkCond(cond)) {
			return;
		}
		uint32_t a = registers.getRegister(ra);
		uint32_t b = registers.getRegister(rb);
		doBinaryFloatOp(op, rd, a, b);
	}

	void floatOpImm(unsigned int cond, FloatOp op, int rd, int ra, int32_t imm) {
		if (!checkCond(cond)) {
			return;
		}
		uint32_t a = registers.getRegister(ra);
		doBinaryFloatOp(op, rd, a, imm);
	}

	void mulhd(unsigned int cond, int rd, int ra, int rb, bool aUnsigned, bool bUnsigned) {
		if (!checkCond(cond)) {
			return;
		}
		uint32_t a = registers.getRegister(ra);
		uint32_t b = registers.getRegister(rb);
		uint32_t result;
		if (aUnsigned && bUnsigned) {
			result = ((uint64_t)a * (uint64_t)b) >> 32;
		} else if (aUnsigned) {
			result = ((int64_t)a * (int64_t)(int32_t)b) >> 32;
		} else if (bUnsigned) {
			result = ((int64_t)(int32_t)a * (int64_t)b) >> 32;
		} else {
			result = ((int64_t)(int32_t)a * (int64_t)(int32_t)b) >> 32;
		}
		registers.setRegister(rd, result);
	}

	void divi(unsigned int cond, int rd, int ra, uint32_t b, bool aUnsigned, bool bUnsigned) {
		if (!checkCond(cond)) {
			return;
		}
		uint32_t a = registers.getRegister(ra);
		if (b == 0) {
			throw std::runtime_error("Division through 0!");
		}
		uint32_t result;
		if (aUnsigned && bUnsigned) {
			result = (uint64_t)a / (uint64_t)b;
		} else if (aUnsigned) {
			result = (int64_t)a / (int64_t)(int32_t)b;
		} else if (bUnsigned) {
			result = (int64_t)(int32_t)a / (int64_t)b;
		} else {
			result = (int64_t)(int32_t)a / (int64_t)(int32_t)b;
		}
		registers.setRegister(rd, result);
	}

        void div(unsigned int cond, int rd, int ra, int rb, bool aUnsigned, bool bUnsigned) {
		log->debug("vc4exec", "div: r%d = r%d / r%d", rd, ra, rb);
                divi(cond, rd, ra, registers.getRegister(rb), aUnsigned, bUnsigned);
        }

	void unk0004() {
		log->debug("vc4exec", "UNK0004");
		registers.setRegister(VC_SR, registers.getRegister(VC_SR) | 0x40000000);
	}

	void unk0005() {
		log->debug("vc4exec", "UNK0005");
		registers.setRegister(VC_SR, registers.getRegister(VC_SR) & ~0x40000000);
	}

private:
	void doLoadStore(bool store, int format, unsigned int rd, uint32_t address) {
		if (store) {
			uint32_t value = registers.getRegister(rd);
			log->debug("vc4exec", "STORE(%d) %08x <= %08x", format, address, value);
			switch (format) {
				case WIDTH_U32:
					memory->writeWord(address, value);
					break;
				case WIDTH_S16:
				case WIDTH_U16:
					memory->writeHalfWord(address, value);
					break;
				case WIDTH_U8:
					memory->writeByte(address, value);
					break;
				default:
					throw std::runtime_error("Invalid load/store format.");
			}
		} else {
			uint32_t value;
			switch (format) {
				case WIDTH_U32:
					value = memory->readWord(address);
					break;
				case WIDTH_U16:
					value = memory->readHalfWord(address);
					break;
				case WIDTH_U8:
					value = memory->readByte(address);
					break;
				case WIDTH_S16:
					value = (int32_t)(int16_t)memory->readHalfWord(address);
					break;
				default:
					throw std::runtime_error("Invalid load/store format.");
			}
			registers.setRegister(rd, value);
		}
	}
	void doBinaryOp(unsigned int op, unsigned int rd, uint32_t a, uint32_t b) {
		if (op >= 0x40) {
			throw std::runtime_error("Invalid operation.");
		}
		log->debug("vc4exec", "Op: %d %08x %08x => r%d", op, a, b, rd);
		switch (op) {
			case OP_MOV:
				registers.setRegister(rd, b);
				break;
			case OP_CMN:
				registers.setRegister(VC_SR, compareAdd(a, b) | (registers.getRegister(VC_SR) & ~0xf));
				break;
			case OP_ADD:
				registers.setRegister(rd, a + b);
				break;
			case OP_BIC:
				registers.setRegister(rd, a & ~b);
				break;
			case OP_MUL:
				registers.setRegister(rd, a * b);
				break;
			case OP_EOR:
				registers.setRegister(rd, a ^ b);
				break;
			case OP_SUB:
				registers.setRegister(rd, a - b);
				break;
			case OP_AND:
				registers.setRegister(rd, a & b);
				break;
			case OP_MVN:
				registers.setRegister(rd, ~b);
				break;
                        case OP_ROR:
                                b &= 31;
                                if (b > 0)
                                        registers.setRegister(rd,
                                            (a >> b) | (a << (32 - b)));
                                else
                                        registers.setRegister(rd, a);
                                break;
			case OP_CMP:
				registers.setRegister(VC_SR, compare(a, b) | (registers.getRegister(VC_SR) & ~0xf));
				break;
			case OP_RSB:
				registers.setRegister(rd, b - a);
				break;
			case OP_BTST:
				registers.setStatus(0x8, (a & (1 << b)) == 0 ? 0xa : 0x0);
				break;
			case OP_OR:
				registers.setRegister(rd, a | b);
				break;
			case OP_EXTU:
				registers.setRegister(rd, a & ((1 << b) - 1));
				break;
			case OP_MAX:
				// TODO: Signed?
				registers.setRegister(rd, a > b ? a : b);
				break;
			case OP_BSET:
				registers.setRegister(rd, a | (1 << b));
				break;
			case OP_MIN:
				// TODO: Signed?
				registers.setRegister(rd, a < b ? a : b);
				break;
			case OP_BCLR: // 18
				registers.setRegister(rd, a & ~(1 << b));
				break;
			case OP_ADDS2: // 19
				registers.setRegister(rd, a + b * 2);
				break;
                        case OP_BITFLIP: // 20
                                registers.setRegister(rd, a ^ (1 << b));
                                break;
			case OP_ADDS4:
				registers.setRegister(rd, a + b * 4);
				break;
			case OP_ADDS8:
				registers.setRegister(rd, a + b * 8);
				break;
			case OP_ADDS16:
				registers.setRegister(rd, a + b * 16);
				break;
			case OP_EXTS:
				{
					unsigned hibit = 1 << (b - 1);
					unsigned mask = (1 << b) - 1;
					if (a & hibit) {
						registers.setRegister(rd,
						  a | ~mask);
					} else {
						registers.setRegister(rd,
						  a & mask);
					}
				}
				break;
			case OP_NEG:
				registers.setRegister(rd, -(int32_t)b);
				break;
			case OP_LSR:
				registers.setRegister(rd, a >> b);
				break;
			case OP_CLZ:
				// TODO: What if a is 0?
				registers.setRegister(rd, __builtin_clz(b));
				break;
			case OP_LSL:
				registers.setRegister(rd, a << b);
				break;
			case OP_ASR:
				if ((a & 0x80000000) == 0) {
					registers.setRegister(rd, a >> b);
				} else {
					registers.setRegister(rd, (a >> b) || (0xffffffff << (32 - b)));
				}
				break;
                        case OP_ABS: // 31
                                registers.setRegister(rd, labs(a));
                                break;
                        case OP_MULHD_UU: // 35
				registers.setRegister(rd, ((uint64_t)a * (uint64_t)b) >> 32);
				//throw std::runtime_error("3Unimplemented operation.");
                                break;
			case OP_ADDSCALE_5:
				registers.setRegister(rd, a + (b << 5));
				break;
			case OP_ADDSCALE_6:
				registers.setRegister(rd, a + (b << 6));
				break;
			case OP_ADDSCALE_7:
				registers.setRegister(rd, a + (b << 7));
				break;
			case OP_ADDSCALE_8:
				registers.setRegister(rd, a + (b << 8));
				break;
			case OP_SUBSCALE_1:
				registers.setRegister(rd, a - (b << 1));
				break;
			case OP_SUBSCALE_2:
				registers.setRegister(rd, a - (b << 2));
				break;
			case OP_SUBSCALE_3:
				registers.setRegister(rd, a - (b << 3));
				break;
			case OP_SUBSCALE_4:
				registers.setRegister(rd, a - (b << 4));
				break;
			case OP_SUBSCALE_5:
				registers.setRegister(rd, a - (b << 5));
				break;
			case OP_SUBSCALE_6:
				registers.setRegister(rd, a - (b << 6));
				break;
			case OP_SUBSCALE_7:
				registers.setRegister(rd, a - (b << 7));
				break;
			case OP_SUBSCALE_8:
				registers.setRegister(rd, a - (b << 8));
				break;
			default:
				throw std::runtime_error("2Unimplemented operation.");
		}
		log->debug("vc4exec", "Result: %08x", registers.getRegister(rd));
	}
	void doBinaryFloatOp(FloatOp op, unsigned int rd, uint32_t ua,
                             uint32_t ub) {
                floatbits a, b;
                a.u = ua;
                b.u = ub;
		floatbits result;
		switch (op) {
			case OP_FADD:
				result.f = a.f + b.f;
				registers.setRegister(rd, result.u);
				break;
			case OP_FSUB:
				result.f = a.f - b.f;
				registers.setRegister(rd, result.u);
				break;
			case OP_FDIV:
				result.f = a.f / b.f;
				registers.setRegister(rd, result.u);
				break;
			case OP_FMUL:
				result.f = a.f * b.f;
				registers.setRegister(rd, result.u);
				break;
			case OP_FCMP:
				registers.setRegister(VC_SR,
                                    compareFloat(a.f, b.f)
				    | (registers.getRegister(VC_SR) & ~0xf));
				break;
			case OP_FABS:
                                result.f = fabsf(b.f);
                                registers.setRegister(rd, result.u);
                                break;
                        case OP_FMAX:
                                result.f = fmaxf(a.f, b.f);
                                registers.setRegister(rd, result.u);
                                break;
                        case OP_FMIN:
                                result.f = fminf(a.f, b.f);
                                registers.setRegister(rd, result.u);
                                break;
                        default:
				throw std::runtime_error("1Unimplemented float operation.");
		}
	}

	bool checkCond(unsigned int cond) {
		return checkCond(cond, registers.getRegister(VC_SR));
	}

	bool checkCond(unsigned int cond, unsigned int status) {
		if (cond >= 16) {
			throw std::runtime_error("Invalid condition.");
		}
		Condition condition = (Condition)(cond >> 1);
		bool result;
#define V(x) ((x & 0x1) != 0)
#define C(x) ((x & 0x2) != 0)
#define N(x) ((x & 0x4) != 0)
#define Z(x) ((x & 0x8) != 0)
		switch (condition) {
			case COND_EQ:
				result = Z(status);
				break;
			case COND_CS:
				result = C(status);
				break;
			case COND_NS:
				result = N(status);
				break;
			case COND_VS:
				result = V(status);
				break;
			case COND_HI:
				result = !C(status) && !Z(status);
				break;
			case COND_GE:
				result = N(status) == V(status);
				break;
			case COND_GT:
				result = N(status) == V(status) && !Z(status);
				break;
			case COND_TRUE:
				result = true;
				break;
			default:
				throw std::runtime_error("Unsupported condition");
		}
		if (cond & 0x1) {
			return !result;
		} else {
			return result;
		}
#undef V
#undef C
#undef N
#undef Z
	}

	unsigned int compare(int32_t a, int32_t b) {
		int status = cc((int64_t)a - (int64_t)b);
                const unsigned int C = 2;
                if ((uint32_t) a < (uint32_t) b)
                  status |= C;
                return status;
	}
	unsigned int compareAdd(int32_t a, int32_t b) {
		int status = cc((int64_t)a + (int64_t)b);
                const unsigned int C = 2;
                if (((int64_t)a + (int64_t)b) & 0x100000000ull)
                  status |= C;
                return status;
	}

	unsigned int compareFloat(float a, float b) {
		unsigned int status = 0;
		if (a == b) {
			status |= 8;
		}
		if (a < b) {
			status |= 6;
		}
		return status;
	}

	unsigned int cc(int64_t result) {
		log->debug("vc4exec", "cc: %016lx", result);
		const unsigned int Z = 8, N = 4, V = 1;
		unsigned int status = 0;
		if (result == 0) {
			status |= Z;
		}
		if (result & 0x80000000) {
			status |= N;
		}
		if (result != (int32_t)result) {
			status |= V;
		}

		return status;
	}

	Memory *memory;
	VideoCoreIVRegisterFile &registers;
	Log *log;
};

#endif
