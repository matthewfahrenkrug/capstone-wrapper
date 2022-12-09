use capstone::arch::x86::{X86InsnDetail, X86OperandType};
use capstone::prelude::DetailsArchInsn;
use itertools::Itertools;
use crate::memory_operand::{MemoryOperandOrRegister8, MemoryOperandOrRegister16, MemoryOperandOrRegister32, MemoryOperandOrRegister64};
use crate::registers::{OperandSize, Register8, Register16, Register32, Register64};

//https://www.felixcloutier.com/x86/adc
#[derive(Debug, PartialEq)]
pub enum AdcInstruction{
    R8Rm8{
        target: MemoryOperandOrRegister8,
        to_add: Register8
    },
    R8dRm8d{
        target: MemoryOperandOrRegister8,
        to_add: Register8
    },
    R16Rm16{
        target: MemoryOperandOrRegister16,
        to_add: Register16
    },
    R32Rm32{
        target: MemoryOperandOrRegister32,
        to_add: Register32
    },
    R64Rm64{
        target: MemoryOperandOrRegister64,
        to_add: Register64
    },
}

impl AdcInstruction {
    pub fn from_details(detail: &X86InsnDetail) -> Self {
        let operands = detail.operands().collect_vec();
        if operands.len() != 2{
            todo!()
        }
        let target_op_size = OperandSize::from_capstone_size(operands[0].size);
        match &operands[0].op_type {
            X86OperandType::Reg(reg_id) => {
                match target_op_size {
                    OperandSize::QuadWord => {
                        let target = MemoryOperandOrRegister64::Reg(Register64::new(*reg_id));
                        match &operands[1].op_type {
                            X86OperandType::Reg(reg_id) => {
                                let to_add = Register64::new(*reg_id);
                                AdcInstruction::R64Rm64 { target, to_add }
                            }
                            X86OperandType::Imm(_) => {
                                todo!()
                            }
                            X86OperandType::Mem(_) => {
                                todo!()
                            }
                            X86OperandType::Invalid => {
                                todo!()
                            }
                        }
                    }
                    OperandSize::DoubleWord => {
                        let target = MemoryOperandOrRegister32::Reg(Register32::new(*reg_id));
                        match &operands[1].op_type {
                            X86OperandType::Reg(reg_id) => {
                                let to_add = Register32::new(*reg_id);
                                AdcInstruction::R32Rm32 { target, to_add }
                            }
                            X86OperandType::Imm(_) => {
                                todo!()
                            }
                            X86OperandType::Mem(_) => {
                                todo!()
                            }
                            X86OperandType::Invalid => {
                                todo!()
                            }
                        }
                    }
                    OperandSize::Word => {
                        let target = MemoryOperandOrRegister16::Reg(Register16::new(*reg_id));
                        match &operands[1].op_type {
                            X86OperandType::Reg(reg_id) => {
                                let to_add = Register16::new(*reg_id);
                                AdcInstruction::R16Rm16 { target, to_add }
                            }
                            X86OperandType::Imm(_) => {
                                todo!()
                            }
                            X86OperandType::Mem(_) => {
                                todo!()
                            }
                            X86OperandType::Invalid => {
                                todo!()
                            }
                        }
                    }
                    OperandSize::HalfWord => {
                        let target = MemoryOperandOrRegister8::Reg(Register8::new(*reg_id));
                        match &operands[1].op_type {
                            X86OperandType::Reg(reg_id) => {
                                let to_add = Register8::new(*reg_id);
                                AdcInstruction::R8Rm8 { target, to_add }
                            }
                            X86OperandType::Imm(_) => {
                                todo!()
                            }
                            X86OperandType::Mem(_) => {
                                todo!()
                            }
                            X86OperandType::Invalid => {
                                todo!()
                            }
                        }
                    }
                }
            }
            X86OperandType::Imm(_) => {
                todo!()
            }
            X86OperandType::Mem(_) => {
                todo!()
            }
            X86OperandType::Invalid => {
                todo!()
            }
        }
    }
}


#[cfg(test)]
pub mod test {
    use std::arch::asm;
    use std::ffi::c_void;
    use crate::{disassemble, function_end_guard};
    use crate::adc_instruction::AdcInstruction;
    use crate::X86Instruction;
    use crate::memory_operand::{MemoryOperandOrRegister8,MemoryOperandOrRegister16, MemoryOperandOrRegister32, MemoryOperandOrRegister64};
    use crate::registers::{Register8, Register16, Register32, Register64};
    use crate::utils::get_function_bytes;

    #[no_mangle]
    fn adc_instruction_variants () {
        unsafe {
            asm!(
            "adc al, bl",
            "adc ax, bx",
            "adc eax, ebx",
            "adc rax, rbx",
            /*
            "adc al, -9",
            "adc ax, -9",
            "adc eax, -9",
            "adc rax, -9",
            "adc byte ptr [rcx], -9",
            "adc word ptr [rdx], -9",
            "adc dword ptr [rax + rcx*8 - 5],  -9",
            "adc qword ptr [rax],  -9",
            "adc [rax], rbx",
            */
            );
            function_end_guard!();
        }
    }

    #[test]
    pub fn disassemble_adc_instruction_variants () {
        let raw_function_ptr = adc_instruction_variants as *const c_void;
        let function_bytes = get_function_bytes(raw_function_ptr);
        let mut res = disassemble(function_bytes, raw_function_ptr as u64).unwrap();
        dbg!(&res);


        assert!(res[1] == X86Instruction::Adc(AdcInstruction::R8Rm8 { target: MemoryOperandOrRegister8::Reg(Register8::AL), to_add: Register8::BL }));

        assert!(res[2] == X86Instruction::Adc(AdcInstruction::R16Rm16 { target: MemoryOperandOrRegister16::Reg(Register16::AX), to_add: Register16::BX }));

        assert!(res[3] == X86Instruction::Adc(AdcInstruction::R32Rm32 { target: MemoryOperandOrRegister32::Reg(Register32::EAX), to_add: Register32::EBX }));

        assert!(res[4] == X86Instruction::Adc(AdcInstruction::R64Rm64 { target: MemoryOperandOrRegister64::Reg(Register64::RAX), to_add: Register64::RBX }));
    }


    #[test]
    pub fn test_adc_r64rm64 () {
        #[no_mangle]
        fn adc_r64rm64() {
            unsafe {
                asm!(
                "adc rax, rbx",
                );
                function_end_guard!();
            }
        }

        let raw_function_ptr = adc_r64rm64 as *const c_void;
        let function_bytes = get_function_bytes(raw_function_ptr);
        let res = disassemble(function_bytes, raw_function_ptr as u64).unwrap();
        assert!(res[1] == X86Instruction::Adc(AdcInstruction::R64Rm64 { target: MemoryOperandOrRegister64::Reg(Register64::RAX), to_add: Register64::RBX }));
    }

    #[test]
    pub fn test_adc_r32rm32 () {
        #[no_mangle]
        fn adc_r32rm32() {
            unsafe {
                asm!(
                "adc eax, ebx",
                );
                function_end_guard!();
            }
        }

        let raw_function_ptr = adc_r32rm32 as *const c_void;
        let function_bytes = get_function_bytes(raw_function_ptr);
        let res = disassemble(function_bytes, raw_function_ptr as u64).unwrap();
        assert!(res[1] == X86Instruction::Adc(AdcInstruction::R32Rm32 { target: MemoryOperandOrRegister32::Reg(Register32::EAX), to_add: Register32::EBX }));
    }



}
