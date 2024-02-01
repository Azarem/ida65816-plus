
#include "m65816.hpp"
#include "util.hpp"
#include "bt.hpp"

//----------------------------------------------------------------------
void m65816_t::handle_operand(const op_t& x, bool read_access, const insn_t& insn)
{
	ea_t ea;
	dref_t dreftype;
	switch (x.type)
	{
	case o_void:
	case o_reg:
		break;

	case o_imm:
		QASSERT(557, read_access);
		dreftype = dr_O;
	MAKE_IMMD:
		set_immd(insn.ea);
		if (is_off(get_flags(insn.ea), x.n))
			insn.add_off_drefs(x, dreftype, x.type == o_imm ? 0 : OOF_ADDR);
		break;

	case o_displ:
		dreftype = read_access ? dr_R : dr_W;
		switch (x.phrase)
		{
		case rD:        // "dp"
		case rDX:       // "dp, X"
		case rDY:       // "dp, Y"
		case riDX:      // "(dp, X)"
		case rDi:       // "(dp,n)"
		case rDiL:      // "long(dp,n)"
		case rDiY:      // "(dp,n), Y"
		case rDiLY:     // "long(dp,n), Y"
		{
			sel_t dp = get_sreg(insn.ea, rD);
			if (dp != BADSEL)
			{
				ea_t orig_ea = dp + x.addr;
				ea = xlat(orig_ea);
				goto MAKE_DREF;
			}
			else
			{
				goto MAKE_IMMD;
			}
		}

		case rAbsi:     // "(abs)"
		case rAbsX:     // "abs, X"
		case rAbsY:     // "abs, Y"
		case rAbsiL:    // "long(abs)"
			ea = xlat(map_data_ea(insn, x));
			goto MAKE_DREF;

		case rAbsXi:    // "(abs,X)"

			//Process jump table
			if (handle_jump_table(insn, x))
				break;

			ea = xlat(map_code_ea(insn, x)); // jmp, jsr
			goto MAKE_DREF;

		case rAbsLX:    // "long abs, X"
			ea = x.addr;
			goto MAKE_DREF;

		default:
			goto MAKE_IMMD;
		}
		break;

	case o_mem:
	case o_mem_far:
		ea = calc_addr(x, nullptr, insn);
	MAKE_DREF:
		insn.create_op_data(ea, x);
		insn.add_dref(ea, x.offb, read_access ? dr_R : dr_W);
		break;

	case o_near:
	case o_far:
	{
		ea_t orig_ea;
		ea = calc_addr(x, &orig_ea, insn);
		if (insn.itype == M65816_per)
		{
			insn.add_dref(ea, x.offb, dr_O);
		}
		else
		{
			bool iscall = is_call_insn(insn);
			cref_t creftype = x.type == o_near
				? iscall ? fl_CN : fl_JN
				: iscall ? fl_CF : fl_JF;
			insn.add_cref(ea, x.offb, creftype);
			if (flow && iscall)
				flow = func_does_return(ea);
		}
	}
	break;

	case o_cop:

		//Only process arguments with an address
		if (x.addr) {
			if (x.dtype == dt_dword)
				ea = xlat(x.addr);
			if (x.specflag3) { //Is code?

				if (x.dtype != dt_dword)
					ea = map_code_ea(insn, x);
				insn.add_cref(ea, x.offb, fl_CN);
			}
			else {
				if (x.dtype != dt_dword)
					ea = map_data_ea(insn, x);
				insn.add_dref(ea, x.offb, read_access ? dr_R : dr_W);
			}
		}

		break;

	default:
		INTERR(558);
	}
}

////----------------------------------------------------------------------
///**
// * Get what is known of the status flags register,
// * at address 'ea'.
// *
// * ea      : The effective address.
// *
// * returns : A 9-bit value, composed with what is known of the
// *           status register at the 'ea' effective address. Its
// *           layout is the following:
// * +----------------------------------------------------------------+
// * | 0 | 0 | 0 | 0 | 0 | M | X | e || n | v | m | x | d | i | z | c |
// * +----------------------------------------------------------------+
// *  15                                7                           0
// *           Note that a 16-bit value is returned, in order to
// *           take the emulation-mode flag into consideration.
// */
//static uint16 get_cpu_status(ea_t ea)
//{
//	return (get_sreg(ea, rFx) ? 0x10 : 0)
//		| (get_sreg(ea, rFm) ? 0x20 : 0)
//		| (get_sreg(ea, rFe) ? 0x100 : 0)
//		| (get_sreg(ea, rOx) ? 0x200 : 0)
//		| (get_sreg(ea, rOm) ? 0x400 : 0);
//}

//----------------------------------------------------------------------

int m65816_t::emu(const insn_t& insn)
{
	uint32 Feature = insn.get_canon_feature(ph);
	flow = ((Feature & CF_STOP) == 0) && !should_stop_flow(insn);

	if (Feature & CF_USE1) handle_operand(insn.Op1, 1, insn);
	if (Feature & CF_USE2) handle_operand(insn.Op2, 1, insn);
	if (Feature & CF_USE3) handle_operand(insn.Op3, 1, insn);
	if (Feature & CF_USE4) handle_operand(insn.Op4, 1, insn);
	if (Feature & CF_USE5) handle_operand(insn.Op5, 1, insn);
	if (Feature & CF_USE6) handle_operand(insn.Op6, 1, insn);
	if (Feature & CF_USE7) handle_operand(insn.Op7, 1, insn);
	if (Feature & CF_USE8) handle_operand(insn.Op8, 1, insn);

	if (Feature & CF_CHG1) handle_operand(insn.Op1, 0, insn);
	if (Feature & CF_CHG2) handle_operand(insn.Op2, 0, insn);
	if (Feature & CF_CHG3) handle_operand(insn.Op3, 0, insn);
	if (Feature & CF_CHG4) handle_operand(insn.Op4, 0, insn);
	if (Feature & CF_CHG5) handle_operand(insn.Op5, 0, insn);
	if (Feature & CF_CHG6) handle_operand(insn.Op6, 0, insn);
	if (Feature & CF_CHG7) handle_operand(insn.Op7, 0, insn);
	if (Feature & CF_CHG8) handle_operand(insn.Op8, 0, insn);

	if (Feature & CF_JUMP)
		remember_problem(PR_JUMP, insn.ea);

	if (flow)
		add_cref(insn.ea, insn.ea + insn.size, fl_F);

	uint8 code = get_byte(insn.ea);
	const struct opcode_info_t& opinfo = get_opcode_info(code);

	if (opinfo.itype == M65816_jmp || opinfo.itype == M65816_jsr)
	{
		if (opinfo.addr == ABS_INDIR
			|| opinfo.addr == ABS_INDIR_LONG
			|| opinfo.addr == ABS_IX_INDIR)
		{
			remember_problem(PR_JUMP, insn.ea);
		}
	}

#if 0
	switch (opinfo.addr)
	{
	case ABS_LONG_IX:
	{
		ea_t orig_ea = insn.Op1.addr;
		ea_t ea = xlat(orig_ea);

		bool read_access;
		if (insn.itype == M65816_sta)
			read_access = false;
		else
			read_access = true;

		insn.add_dref(ea, insn.Op1.offb, read_access ? dr_R : dr_W);
		break;
	}

	case DP:
	{
		bool read_access;
		if (insn.itype == M65816_tsb || insn.itype == M65816_asl || insn.itype == M65816_trb
			|| insn.itype == M65816_rol || insn.itype == M65816_lsr || insn.itype == M65816_ror
			|| insn.itype == M65816_dec || insn.itype == M65816_inc)
			read_access = false;
		else
			read_access = true;

		int32 val = backtrack_value(insn.ea, 2, BT_DP);
		if (val != -1)
		{
			ea_t orig_ea = val + insn.Op1.addr;
			ea_t ea = xlat(orig_ea);

			insn.create_op_data(ea, insn.Op1);
			insn.add_dref(ea, insn.Op1.offb, read_access ? dr_R : dr_W);
		}
	}
	break;
	}
#endif

	switch (insn.itype)
	{
	case M65816_sep:
	case M65816_rep:
	{
		// Switching 8 -> 16 bits modes.
		uint8 flag_data = get_byte(insn.ea + 1);
		uint8 m_flag = flag_data & 0x20;
		uint8 x_flag = flag_data & 0x10;
		uint8 val = (insn.itype == M65816_rep) ? 0 : 1;


		if (m_flag) {
			split_sreg_range(insn.ea + 2, rFm, val, SR_auto);
			split_sreg_range(insn.ea + 2, rOm, val ? 0 : 1, SR_auto);
		}
		if (x_flag) {
			split_sreg_range(insn.ea + 2, rFx, val, SR_auto);
			split_sreg_range(insn.ea + 2, rOx, val ? 0 : 1, SR_auto);
		}
	}
	break;

	case M65816_xce:
	{
		// Switching to native mode?
		uint8 prev = get_byte(insn.ea - 1);
		const struct opcode_info_t& opinf = get_opcode_info(prev);
		if (opinf.itype == M65816_clc)
			split_sreg_range(insn.ea + 1, rFe, 0, SR_auto);
		else if (opinf.itype == M65816_sec)
			split_sreg_range(insn.ea + 1, rFe, 1, SR_auto);
	}
	break;

	case M65816_jmp:
	case M65816_jml:
	case M65816_jsl:
	case M65816_jsr:
	{
		if (insn.Op1.full_target_ea)
		{
			ea_t ftea = insn.Op1.full_target_ea;
			if (insn.itype != M65816_jsl && insn.itype != M65816_jml)
				ftea = map_code_ea(insn, ftea, 0);
			else
				ftea = xlat(ftea);

			xfer_sregs(insn, ftea);

			//split_sreg_range(ftea, rFm, get_sreg(insn.ea, rFm), SR_auto);
			//split_sreg_range(ftea, rFx, get_sreg(insn.ea, rFx), SR_auto);
			//split_sreg_range(ftea, rFe, get_sreg(insn.ea, rFe), SR_auto);
			//split_sreg_range(ftea, rPB, ftea >> 16, SR_auto);
			//split_sreg_range(ftea, rB, get_sreg(insn.ea, rB), SR_auto);
			//split_sreg_range(ftea, rDs, get_sreg(insn.ea, rDs), SR_auto);
			//split_sreg_range(ftea, rD, get_sreg(insn.ea, rD), SR_auto);

			if (insn.itype == M65816_jsl || insn.itype == M65816_jsr) {

				func_t* func = get_func(ftea);
				if (!func) {
					add_func(ftea);
					func = get_func(ftea);
				}

				if (func)
					xfer_sregs_return(insn, func);
			}
		}
	}
	break;

	case M65816_plb:
	{
		int32 val = backtrack_value(insn.ea, 1, BT_STACK);
		if (val != -1)
		{
			split_sreg_range(insn.ea + insn.size, rB, val, SR_auto);
			split_sreg_range(insn.ea + insn.size, rDs, val << 12, SR_auto);
		}
	}
	break;

	case M65816_pld:
	{
		int32 val = backtrack_value(insn.ea, 2, BT_STACK);
		if (val != -1)
			split_sreg_range(insn.ea + insn.size, rD, val, SR_auto);
	}
	break;

	case M65816_plp:
	{
		// Ideally, should pass another parameter, specifying when to stop
		// backtracking.
		// For example, in order to avoid this:
		//     PHP
		//     PLP <-- this one is causing interference
		//             (dunno if that even happens, though)
		//     PLP
		ea_t ea = backtrack_prev_ins(insn.ea, M65816_php);
		if (ea != BADADDR)
		{
			xfer_sregs_short(ea, insn.ea + insn.size);
			/*		uint16 p = get_cpu_status(ea);
					split_sreg_range(insn.ea + insn.size, rFm, (p >> 5) & 0x1, SR_auto);
					split_sreg_range(insn.ea + insn.size, rFx, (p >> 4) & 0x1, SR_auto);
					split_sreg_range(insn.ea + insn.size, rOm, (p >> 10) & 0x1, SR_auto);
					split_sreg_range(insn.ea + insn.size, rOx, (p >> 9) & 0x1, SR_auto);*/
		}
	}
	break;

	//case M65816_bcc:
	//case M65816_bcs:
	//case M65816_beq:
	//case M65816_bmi:
	//case M65816_bne:
	//case M65816_bpl:
	//case M65816_bra:
	//case M65816_bvc:
	//case M65816_bvs:
	//case M65816_brl:

	//	{
	//		ea_t ftea = map_code_ea(insn, insn.Op1);

	//		split_sreg_range(ftea, rFm, get_sreg(insn.ea, rFm), SR_auto);
	//		split_sreg_range(ftea, rFx, get_sreg(insn.ea, rFx), SR_auto);
	//	}

	//	break;
	}

	return 1;
}

