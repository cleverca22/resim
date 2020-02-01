#include "videocore/VideoCoreIVProcessor.hpp"

void VectorFile::write32(uint8_t row, uint8_t col, uint32_t value) {
  vectorFile[row][col] =       value & 0x000000ff;
  vectorFile[row][col + 16] = (value & 0x0000ff00) >> 8;
  vectorFile[row][col + 32] = (value & 0x00ff0000) >> 16;
  vectorFile[row][col + 48] = (value & 0xff000000) >> 24;
}

uint32_t VectorFile::read32(uint8_t row, uint8_t col) {
  return (vectorFile[row][col+48] << 24)
       | (vectorFile[row][col+32] << 16)
       | (vectorFile[row][col+16] <<  8)
       | (vectorFile[row][col]);
}
