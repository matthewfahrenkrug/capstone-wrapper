use capstone::arch;
use capstone::arch::x86::X86Insn;
use capstone::prelude::{BuildsCapstone, BuildsCapstoneSyntax};
use thiserror::Error;

use crate::adc_instruction::AdcInstruction;
use crate::add_instruction::AddInstruction;
use crate::condition_code_flag::JumpConditionCode;
use crate::jcc_instruction::{JCCInstruction};
use crate::mov_instruction::MovInstruction;
use crate::push_instruction::PushInstruction;
use crate::ret_instruction::RetInstruction;
use crate::setb_instruction::SetBInstruction;
use crate::shl_instruction::ShlInstruction;
use crate::sub_instruction::SubInstruction;
use crate::test_instruction::TestInstruction;

#[derive(Error, Debug)]
pub enum DisassembleError {
    #[error("Failed to disassemble")]
    FailedToDisassemble,
    #[error("Failed to configure capstone")]
    FailedToConfigureCapstone,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ImmediateOperand {
    Imm8(i8),
    Imm16(i16),
    Imm32(i32),
}

impl ImmediateOperand {
    pub fn from_capstone_displacement(capstone_displacement: i64) -> ImmediateOperand {
        let res: i32 = capstone_displacement.try_into().expect("But x86 doesn't have 64 bit displacements?");
        ImmediateOperand::Imm32(res)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum X86Scale {
    One,
    Two,
    Four,
    Eight,
}

impl X86Scale {
    pub fn from_capstone_scale(capstone_scale: i32) -> X86Scale {
        match capstone_scale {
            1 => X86Scale::One,
            2 => X86Scale::Two,
            4 => X86Scale::Four,
            8 => X86Scale::Eight,
            _ => {
                panic!("Unexpected scale?")
            }
        }
    }
}

pub mod memory_operand;
pub mod registers;

pub mod condition_code_flag {
    #[derive(Debug, Eq, PartialEq)]
    pub enum JumpConditionCode {
        A,
        AE,
        B,
        BE,
        C,
        CXZ,
        E,
        ECXZ,
        G,
        GE,
        L,
        LE,
        NA,
        NAE,
        NB,
        NBE,
        NC,
        NE,
        NG,
        NGE,
        NL,
        NLE,
        NO,
        NP,
        NS,
        NZ,
        O,
        P,
        PE,
        PO,
        S,
        Z,
    }
}

pub mod push_instruction;
pub mod mov_instruction;
pub mod shl_instruction;
pub mod add_instruction;
pub mod adc_instruction;
pub mod sub_instruction;
pub mod setb_instruction;
pub mod test_instruction;
pub mod jcc_instruction;
pub mod ret_instruction;
pub mod utils;

#[derive(Debug, Eq, PartialEq)]
pub enum X86Instruction {
    Push(PushInstruction),
    Mov(MovInstruction),
    Shl(ShlInstruction),
    Add(AddInstruction),
    Adc(AdcInstruction),
    Sub(SubInstruction),
    SetB(SetBInstruction),
    Test(TestInstruction),
    JCC(JCCInstruction),
    Ret(RetInstruction),
}

pub fn disassemble(bytes: &[u8], address: u64) -> Result<Vec<X86Instruction>, DisassembleError> {
    let capstone = capstone::Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Shouldn't fail to instantiate capstone.");
    let instructions = capstone.disasm_all(bytes, address).map_err(|_| DisassembleError::FailedToDisassemble)?;
    instructions.iter().map(|instruction| {
        let instruction_type = X86Insn::from(instruction.id().0);
        let details = capstone.insn_detail(instruction).map_err(|_| DisassembleError::FailedToDisassemble)?;
        let arch_detail = details.arch_detail();
        let x86_detail = arch_detail.x86().ok_or(DisassembleError::FailedToDisassemble)?;
        Ok(match instruction_type {
            X86Insn::X86_INS_PUSH => {
                X86Instruction::Push(PushInstruction::from_detail(x86_detail))
            }
            X86Insn::X86_INS_MOV => {
                X86Instruction::Mov(MovInstruction::from_detail(x86_detail))
            }
            X86Insn::X86_INS_SHL => {
                X86Instruction::Shl(ShlInstruction::from_details(x86_detail))
            }
            X86Insn::X86_INS_SUB => {
                X86Instruction::Sub(SubInstruction::from_details(x86_detail))
            }
            X86Insn::X86_INS_ADD => {
                X86Instruction::Add(AddInstruction::from_details(x86_detail))
            }
            X86Insn::X86_INS_ADC => {
                X86Instruction::Adc(AdcInstruction::from_details(x86_detail))
            }
            X86Insn::X86_INS_SETB => {
                X86Instruction::SetB(SetBInstruction::from_details(x86_detail))
            }
            X86Insn::X86_INS_TEST => {
                X86Instruction::Test(TestInstruction::from_details(x86_detail))
            }
            X86Insn::X86_INS_JBE => {
                X86Instruction::JCC(JCCInstruction::from_details(instruction, x86_detail, JumpConditionCode::BE))
            }
            X86Insn::X86_INS_JNE => {
                X86Instruction::JCC(JCCInstruction::from_details(instruction, x86_detail, JumpConditionCode::NE))
            }
            X86Insn::X86_INS_RET => {
                X86Instruction::Ret(RetInstruction::from_details(x86_detail))
            }
            _ => {
                todo!("Unimplemented instruction id: {}", instruction.id().0)
            }
        })
    }).collect::<Result<Vec<_>, _>>()
}


#[cfg(test)]
mod tests;
