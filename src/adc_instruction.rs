use capstone::arch::x86::{X86InsnDetail, X86OperandType};
use capstone::prelude::DetailsArchInsn;
use itertools::Itertools;
use crate::memory_operand::{MemoryOperandOrRegister8, MemoryOperandOrRegister16, MemoryOperandOrRegister32, MemoryOperandOrRegister64, MemoryOperand};
use crate::registers::{OperandSize, Register8, Register16, Register32, Register64};
use crate::utils::{imm_i8, imm_i16, imm_i32};

//https://www.felixcloutier.com/x86/adc
#[derive(Debug, PartialEq)]
pub enum AdcInstruction{
    ALimm8 {
        imm8: i8
    },
    AXimm16 {
        imm8: i16
    },
    EAXimm32 {
        imm16: i32
    },
    RAXimm32 {
        imm32: i32
    },
    Rm8imm8 {
        target: MemoryOperandOrRegister8,
        imm8: i8,
    },
    Rm16imm16 {
        target: MemoryOperandOrRegister16,
        imm16: i16,
    },
    Rm32imm32 {
        target: MemoryOperandOrRegister32,
        imm32: i32,
    },
    Rm64imm32 {
        target: MemoryOperandOrRegister64,
        imm32: i32,
    },
    Rm16imm8 {
        target: MemoryOperandOrRegister16,
        imm8: i8,
    },
    Rm32imm8 {
        target: MemoryOperandOrRegister32,
        imm8: i8,
    },
    Rm64imm8 {
        target: MemoryOperandOrRegister64,
        imm8: i8,
    },
    Rm8R8{
        target: Register8,
        to_add: MemoryOperandOrRegister8,
    },
    Rm16R16{
        target: Register16,
        to_add: MemoryOperandOrRegister16,
    },
    Rm32R32{
        target: Register32,
        to_add: MemoryOperandOrRegister32,
    },
    Rm64R64{
        target: Register64,
        to_add: MemoryOperandOrRegister64,
    },
    R8Rm8{
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
                            X86OperandType::Imm(imm) => {
                                match OperandSize::from_capstone_size(operands[1].size) {
                                    OperandSize::QuadWord => {
                                        AdcInstruction::Rm64imm32 { target, imm32: imm_i32(*imm) }
                                    }
                                    OperandSize::DoubleWord |
                                    OperandSize::Word => {
                                        panic!("Unexpected constant size")
                                    }
                                    OperandSize::HalfWord => {
                                        AdcInstruction::Rm64imm8 { target, imm8: imm_i8(*imm) }
                                    }
                                }
                            }
                            X86OperandType::Mem(mem) => {
                                dbg!("64bit mem");
                                dbg!(&mem);
                                let second = MemoryOperand::from_mem(mem);
                                dbg!(second);
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
                            X86OperandType::Imm(imm) => {
                                match OperandSize::from_capstone_size(operands[1].size) {
                                    OperandSize::DoubleWord => {
                                        AdcInstruction::Rm32imm32 { target, imm32: imm_i32(*imm) }
                                    }
                                    OperandSize::QuadWord |
                                    OperandSize::Word => {
                                        panic!("Unexpected constant size")
                                    }
                                    OperandSize::HalfWord => {
                                        AdcInstruction::Rm32imm8 { target, imm8: imm_i8(*imm) }
                                    }
                                }
                            }
                            X86OperandType::Mem(mem) => {
                                dbg!("32bit mem");
                                dbg!(&mem);
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
                            X86OperandType::Imm(imm) => {
                                match OperandSize::from_capstone_size(operands[1].size) {
                                    OperandSize::QuadWord |
                                    OperandSize::DoubleWord => {
                                        panic!("Unexpected large constant")
                                    }
                                    OperandSize::Word => {
                                        AdcInstruction::Rm16imm16 { target, imm16: imm_i16(*imm) }
                                    }
                                    OperandSize::HalfWord => {
                                        AdcInstruction::Rm16imm8 { target, imm8: imm_i8(*imm) }
                                    }
                                }
                            }
                            X86OperandType::Mem(mem) => {
                                dbg!("16bit mem");
                                dbg!(&mem);
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
                            X86OperandType::Imm(imm) => {
                                assert_eq!(OperandSize::from_capstone_size(operands[1].size), OperandSize::HalfWord);
                                AdcInstruction::Rm8imm8 { target, imm8: imm_i8(*imm) }
                            }
                            X86OperandType::Mem(mem) => {
                                dbg!("8bit mem");
                                dbg!(&mem);
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
            X86OperandType::Mem(mem) => {
                dbg!("mem first");
                dbg!(&mem);
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
            "adc al, -9",
            "adc ax, -9",
            "adc eax, -9",
            "adc rax, -9",
            //"adc byte ptr [rcx], -9",
            //"adc word ptr [rdx], -99",
            //"adc dword ptr [rax + rcx*8 - 5],  -999",
            //"adc qword ptr [rax],  -9999",
            //"adc word ptr [rdx], 257",
            //"adc dword ptr [rax + rcx*8 - 5],  -900000",
            //"adc qword ptr [rax],  900999",
            //"adc byte ptr [rax],  bl",
            //"adc word ptr [rax],  cx",
            //"adc dword ptr [rax],  edx",
            //"adc qword ptr [rax],  r9",
            //"adc bl, byte ptr [rax]",
            //"adc cx, word ptr [rax]",
            //"adc edx, dword ptr [rax]",
            "adc r9, qword ptr [rax]",
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


        //assert!(res[1] == X86Instruction::Adc(AdcInstruction::R8Rm8 { target: MemoryOperandOrRegister8::Reg(Register8::AL), to_add: Register8::BL }));
        //assert!(res[2] == X86Instruction::Adc(AdcInstruction::R16Rm16 { target: MemoryOperandOrRegister16::Reg(Register16::AX), to_add: Register16::BX }));
        //assert!(res[3] == X86Instruction::Adc(AdcInstruction::R32Rm32 { target: MemoryOperandOrRegister32::Reg(Register32::EAX), to_add: Register32::EBX }));
        //assert!(res[4] == X86Instruction::Adc(AdcInstruction::R64Rm64 { target: MemoryOperandOrRegister64::Reg(Register64::RAX), to_add: Register64::RBX }));
    }



    #[test]
    pub fn test_adc_r8rm8 () {
        #[no_mangle]
        fn adc_r8rm8 () {
            unsafe {
                asm!(
                "adc al, bl",
                );
                function_end_guard!();
            }
        }

        let raw_function_ptr = adc_r8rm8 as *const c_void;
        let function_bytes = get_function_bytes(raw_function_ptr);
        let res = disassemble(function_bytes, raw_function_ptr as u64).unwrap();
        assert!(res[1] == X86Instruction::Adc(AdcInstruction::R8Rm8 { target: MemoryOperandOrRegister8::Reg(Register8::AL), to_add: Register8::BL }));
    }

    #[test]
    pub fn test_adc_r16rm16 () {
        #[no_mangle]
        fn adc_r16rm16() {
            unsafe {
                asm!(
                "adc ax, bx",
                );
                function_end_guard!();
            }
        }

        let raw_function_ptr = adc_r16rm16 as *const c_void;
        let function_bytes = get_function_bytes(raw_function_ptr);
        let res = disassemble(function_bytes, raw_function_ptr as u64).unwrap();
        assert!(res[1] == X86Instruction::Adc(AdcInstruction::R16Rm16 { target: MemoryOperandOrRegister16::Reg(Register16::AX), to_add: Register16::BX }));
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



}
