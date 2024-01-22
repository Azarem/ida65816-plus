#pragma once
#ifndef __UTIL_HPP__
#define __UTIL_HPP__

#include "m65816.hpp"

#define MAX_OFFSET  0x1000L
//#define DEFAULT_BASE 0x800000L

/// <summary>
/// Calculates the absolute distance between two addresses
/// </summary>
/// <param name="start"></param>
/// <param name="end"></param>
/// <returns></returns>
static inline long ea_dist(ea_t start, ea_t end) {
	return abs((long)start - (long)end);
}

/// <summary>
/// Compares the absolute distance between two addresses against a maximum value
/// </summary>
/// <param name="start"></param>
/// <param name="end"></param>
/// <param name="max"></param>
/// <returns></returns>
static inline long ea_dist_max(ea_t start, ea_t end, long max = MAX_OFFSET) {
	return ea_dist(start, end) <= max;
}

/// <summary>
/// Attempts to make operand at ea_t into a code offset, while keeping the calculated base from ea_t
/// </summary>
/// <param name="ea"></param>
/// <returns></returns>
static inline bool ea_make_offset(ea_t ea) {
	return op_plain_offset(ea, OPND_ALL, ea & ~0xFFFFL);
}

/// <summary>
/// Read a specified word (stored at ea_t) and map it to a code address, using insn_t for the segment base
/// </summary>
/// <param name="insn">Instruction to be used as the caller / base</param>
/// <param name="ea">Address of value to be "read"</param>
/// <returns>Returns new effective address stored at ea</returns>
static inline ea_t ea_map_code(const insn_t& insn, ea_t ea) {
	return map_code_ea(insn, get_word(ea), 0);
}

/// <summary>
/// Test to see if instruction is a function call
/// </summary>
/// <param name="insn"></param>
/// <returns></returns>
static inline bool is_call(const insn_t& insn) {
	return has_insn_feature(insn.itype, CF_CALL);
}

/// <summary>
/// 
/// </summary>
/// <param name="insn"></param>
/// <param name="ea"></param>
static void xfer_sreg(ea_t from, ea_t to) {
	split_sreg_range(to, rFm, get_sreg(from, rFm), SR_auto);
	split_sreg_range(to, rFx, get_sreg(from, rFx), SR_auto);
	split_sreg_range(to, rFe, get_sreg(from, rFe), SR_auto);
	split_sreg_range(to, rPB, to >> 16, SR_auto);
	split_sreg_range(to, rB, get_sreg(from, rB), SR_auto);
	split_sreg_range(to, rDs, get_sreg(from, rDs), SR_auto);
	split_sreg_range(to, rD, get_sreg(from, rD), SR_auto);
}

/// <summary>
/// Process a jump table entry, creating the data offset and code reference
/// </summary>
/// <param name="insn">Original instruction referencing the jump table</param>
/// <param name="ea">Address for current entry in the jump table</param>
/// <returns>Returns true if success, otherwise false</returns>
static bool make_jt_offset(const insn_t& insn, ea_t ea) {
	//Read entry value
	ea_t ref = ea_map_code(insn, ea);

	//Validate distance
	if (ea_dist(ea, ref) > MAX_OFFSET)
		return false;

	//Create data offset
	if (!ea_make_offset(ea))
		return false;

	//Add code reference
	if (add_cref(ea, ref, is_call(insn) ? fl_CN : fl_JN)) {
		//Update segment registers at new address
		xfer_sreg(insn.ea, ref);
		return true;
	}

	return false;
}

/// <summary>
/// 
/// </summary>
/// <param name="insn"></param>
/// <param name="x"></param>
/// <returns></returns>
static bool handle_jump_table(const insn_t& insn, const op_t& x) {

	if (insn.itype == M65816_jsr || insn.itype == M65816_jmp) {
		ea_t ea = map_code_ea(insn, x);

		ea_t cur = ea;
		while (make_jt_offset(insn, cur))
			cur += 2;

		//TODO: Make subroutine chunk
		return true;
	}

	return false;
}

#endif