// For 68k code that uses software floating point routines (lke Apple SANE), storage operations on doubles
// will likely be split across two 32-bit instructions. To make the decompiler look nicer, you can import this
// header and ensure all doubles use it to avoid Ghidra's default ugly decompilation of these operations.
//
// Instead of this:
//   *(undefined4 *)&(this->_pausedTime)._time = currentRuntime._time._0_4_;
//   *(undefined4 *)((int)&(this->_pausedTime)._time + 4) = currentRuntime._time._4_4_;
// You should get this:
//   (this->_pauseStartTime)._time.parts.high = currentRuntime._time.parts.high;
//    (this->_pauseStartTime)._time.parts.low = currentRuntime._time.parts.low;

union double68k {
    double value;
    struct {
        uint32_t high;
        uint32_t low;
    } parts;
};