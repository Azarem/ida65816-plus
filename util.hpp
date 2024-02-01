#pragma once
#ifndef __UTIL_HPP__
#define __UTIL_HPP__

#include "m65816.hpp"
#include "struct.hpp"
#include "ida/gaia_cop.hpp"

#define MAX_OFFSET  0x6000L
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

///// <summary>
///// Test to see if instruction is a function call
///// </summary>
///// <param name="insn"></param>
///// <returns></returns>
//static inline bool is_call(const insn_t& insn) {
//	return has_insn_feature(insn.itype, CF_CALL);
//}


static void xfer_sreg(ea_t from, ea_t to, int rg, bool is_call = false) {
	sel_t val;

	if (rg == rPB)
		val = (to >> 16) & 0xFF;

	else if (rg == rFm || rg == rFx) {

		sreg_range_t range, other;
		int org = rg == rFm ? rOm : rOx;

		bool has_range = get_sreg_range(&range, from, rg);
		bool has_other = get_sreg_range(&other, from, org);

		if (has_range) {
			if (has_other) {
				if (other.start_ea > range.start_ea)
					goto OTH;
				else if (range.start_ea > other.start_ea) {}
				else if (range.val == other.val)
					return; //Do nothing
				else if (other.val)
					goto OTH;
			}
			val = range.val;
		}
		else if (has_other) {
		OTH:
			rg = org;
			val = other.val;
		}
		else
			val = 0;
	}
	else
		val = get_sreg(from, rg);

	////Do nothing if there is no change
	//if (!is_call) {
	//	sel_t cur = get_sreg(to, rg);
	//	if (val == cur)
	//		return;
	//}

RET:
	split_sreg_range(to, rg, val, SR_auto);
}

static inline void xfer_sreg(const insn_t& insn, ea_t to, int rg) {
	xfer_sreg(insn.ea, to, rg, is_call_insn(insn));
}

static void xfer_sregs_short(ea_t from, ea_t to, bool is_call = false) {
	xfer_sreg(from, to, rFm, is_call);
	xfer_sreg(from, to, rFx, is_call);
}

static inline void xfer_sregs_short(const insn_t& insn, ea_t to) {
	xfer_sregs_short(insn.ea, to, is_call_insn(insn));
}

/// <summary>
/// 
/// </summary>
/// <param name="insn"></param>
/// <param name="ea"></param>
static void xfer_sregs(ea_t from, ea_t to, bool is_call = false) {
	xfer_sreg(from, to, rFm, is_call);
	xfer_sreg(from, to, rFx, is_call);
	xfer_sreg(from, to, rFe, is_call);
	xfer_sreg(from, to, rPB, is_call);
	xfer_sreg(from, to, rB, is_call);
	xfer_sreg(from, to, rDs, is_call);
	xfer_sreg(from, to, rD, is_call);
}

static inline void xfer_sregs(const insn_t& insn, ea_t to) {
	xfer_sregs(insn.ea, to, is_call_insn(insn));
}

static void xfer_sreg_return(const insn_t& insn, func_t* func, int rg) {

	ea_t to = insn.ea + insn.size;

	if (to == 0xC2A6B7) {
		msg("");
	}

	sel_t old = get_sreg(insn.ea, rg);
	sel_t near = get_sreg(func->start_ea, rg);
	sel_t far0 = get_sreg(func->end_ea, rg);
	sel_t far1 = get_sreg(func->end_ea - 1, rg);
	sel_t far2 = get_sreg(func->end_ea - 2, rg);


	if (near != far1 && far1 != old) {
		split_sreg_range(to, rg, far1, SR_auto);
	}
}

static bool is_func_wrapped(ea_t start, ea_t end) {
	ea_t cur = start;
	bool is_stacked = false, is_wrapped = false;
	insn_t ins = insn_t();

	for (int x = 0; x < 4; x++) {
		decode_insn(&ins, cur);
		if (ins.itype == M65816_php) {
			is_stacked = true;
			break;
		}
		cur += ins.size;
	}

	if (is_stacked) {
		cur = end;
		for (int x = 0; x < 4; x++) {
			cur = decode_prev_insn(&ins, cur);
			if (ins.itype == M65816_plp) {
				is_wrapped = true;
				break;
			}
		}
	}

	return is_wrapped;
}


static void xfer_sregs_return(const insn_t& insn, func_t* func) {

	//If register is pushed and popped, do nothing
	if (!is_func_wrapped(func->start_ea, func->end_ea))
	{
		xfer_sreg_return(insn, func, rFm);
		xfer_sreg_return(insn, func, rFx);
	}
}

/// <summary>
/// Process a jump table entry, creating the data offset and code reference
/// </summary>
/// <param name="insn">Original instruction referencing the jump table</param>
/// <param name="ea">Address for current entry in the jump table</param>
/// <returns>Returns true if success, otherwise false</returns>
static bool make_jt_offset(const insn_t& insn, ea_t ea, ea_t& near) {
	//Read entry value
	ea_t ref = ea_map_code(insn, ea);

	if (ref <= ea)
	{
		msg("reverse ref 0x%04X -> 0x%04X -> 0x%04X\n", insn.ea, ea, ref);
		return false;
	}

	if (near != 0 && ea + 1 >= near)
	{
		msg("bump 0x%04X -> 0x%04X -> 0x%04X\n", insn.ea, ea, ref);
		return false;
	}

	//Validate distance
	if (ea_dist(ea, ref) > MAX_OFFSET)
	{
		msg("distance too far 0x%04X -> 0x%04X -> 0x%04X\n", insn.ea, ea, ref);
		return false; //To continue or not...
	}

	//Create data offset
	if (!ea_make_offset(ea))
	{
		msg("make_offset failed 0x%04X -> 0x%04X -> 0x%04X\n", insn.ea, ea, ref);
		return false;
	}

	//Add code reference
	if (add_cref(ea, ref, is_call_insn(insn) ? fl_CN : fl_JN)) {
		//Update segment registers at new address
		xfer_sregs(insn, ref);

		if (near == 0 || (ref > ea && ref < near))
			near = ref;

		return true;
	}

	msg("add_cref failed 0x%04X -> 0x%04X -> 0x%04X\n", insn.ea, ea, ref);
	return false;
}

static bool should_stop_flow(const insn_t& insn) {
	if (insn.itype == M65816_cop) {
		const cop_def& def = cop_lst[insn.ops[0].value & 0xFF];
		return def.noret;
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

		ea_t cur = ea, near = 0;
		while (make_jt_offset(insn, cur, near))
			cur += 2;


		//TODO: Make subroutine chunk
		return true;
	}

	return false;
}

static const char hex_table[16] = {
	'0',
	'1',
	'2',
	'3',
	'4',
	'5',
	'6',
	'7',
	'8',
	'9',
	'A',
	'B',
	'C',
	'D',
	'E',
	'F'
};

static uint64 get_next_triple(insn_t& insn) {
	return insn.get_next_word() | ((uint64)insn.get_next_byte() << 16);
}

/// <summary>
/// Extends instruction out to multiple operands based on the COP command byte, using cop_lst as the definition
/// </summary>
/// <param name="insn"></param>
static bool process_cop(insn_t& insn) {
	//Continue only for cop instruction
	if (insn.itype != M65816_cop)
		return false;

	//Get definition
	op_t* op = insn.ops;
	const cop_def& def = cop_lst[op->value];

	//Sanity check
	if (def.op != op->value)
		return false;

	//Iterate through the command bytes
	for (char ix = 0, off = 1, cmd = -1; ix < 8 && cmd != 0; op++, cmd = def.mem[ix++]) {
		switch (cmd) {

		case -1: break; //Start

		case 'b': //Byte
			op->value = insn.get_next_byte();
			op->dtype = dt_byte;
			break;

		case 'c': //Code
			op->specflag3 = 1; //Flag code
		case 'o': //Offset
			op->addr = insn.get_next_word();
			goto INC;

		case 'w': //Short word
			op->value = insn.get_next_word();
		INC:
			op->dtype = dt_word;
			break;

		case 'C': //Long code
			op->specflag3 = 1; //Flag code
		case 'O': //Long offset
			op->addr = get_next_triple(insn);
			goto WIDE;

		case 'W': //Long word
			op->value = get_next_triple(insn);
		WIDE:
			op->dtype = dt_dword;
			break;

		default: goto NEXT; //Invalid command
		}

		//Assign common fields
		op->type = o_cop;
		op->offb = off;

		//Increment offset
		off += op->dtype == dt_dword ? 3
			: op->dtype == dt_word ? 2 : 1;
	}

NEXT:
	return true; //Done
}

#endif