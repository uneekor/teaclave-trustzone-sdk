// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#![cfg_attr(not(feature = "std"), no_std)]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
    DataFlag, PersistentObject, Random,
};
use optee_utee::{AlgorithmId, Digest};
use optee_utee::{ErrorKind, Parameters, Result};
use proto::Command;

pub struct DigestOp {
    pub op: Digest,
}

const SEC_KEY_SIZE: usize = 64;

impl Default for DigestOp {
    // This is related to our TA session context design, which requires the struct to implement
    // the Default trait. Revising this design should be future work, so temporary allow the unwrap() usage.
    #[allow(clippy::unwrap_used)]
    fn default() -> Self {
        let op = Digest::allocate(AlgorithmId::Sha256).unwrap();
        let mut key_buffer = [0u8; SEC_KEY_SIZE];
        let mut ctx = DigestOp { op };
        match PersistentObject::open(
            optee_utee::ObjectStorageConstants::Private,
            "root_key".as_bytes(),
            DataFlag::ACCESS_READ,
        ) {
            Ok(obj) => {
                let len = obj.read(&mut key_buffer).unwrap();
                trace_println!("Read key from storage. Len: {}, Key: {:?}", len, key_buffer);
                trace_println!("Update digest with key");
                ctx.op.update(&key_buffer);
            }
            Err(_) => {
                trace_println!("Key not found");
                generate_key(&mut ctx).unwrap();
            }
        }

        ctx
    }
}

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters, _sess_ctx: &mut DigestOp) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut DigestOp) {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}

#[ta_invoke_command]
fn invoke_command(sess_ctx: &mut DigestOp, cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::UpdateDigest => update(sess_ctx, params),
        Command::DoFinal => do_final(sess_ctx, params),
        Command::ResetKey => generate_key(sess_ctx),
        _ => Err(ErrorKind::BadParameters.into()),
    }
}

pub fn generate_key(sess_ctx: &mut DigestOp) -> Result<()> {
    trace_println!("generate new key...");
    let mut key_buffer = [0; SEC_KEY_SIZE];
    Random::generate(&mut key_buffer);
    let mut obj = PersistentObject::create(
        optee_utee::ObjectStorageConstants::Private,
        "root_key".as_bytes(),
        DataFlag::OVERWRITE | DataFlag::ACCESS_WRITE,
        None,
        &[],
    )?;
    obj.write(&key_buffer)?;
    trace_println!(
        "Create and Write Key to storage. Len: {}, Key: {:?}",
        key_buffer.len(),
        key_buffer
    );
    sess_ctx.op.reset();
    sess_ctx.op.update(&key_buffer);

    Ok(())
}

pub fn update(ctx: &mut DigestOp, params: &mut Parameters) -> Result<()> {
    let mut p = unsafe { params.0.as_memref()? };
    let buffer = p.buffer();
    trace_println!("[+] Update Digest with {:?}", buffer);
    ctx.op.update(buffer);
    Ok(())
}

pub fn do_final(ctx: &mut DigestOp, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref()? };
    let mut p1 = unsafe { params.1.as_memref()? };
    let mut p2 = unsafe { params.2.as_value()? };
    let input = p0.buffer();
    trace_println!("[+] Do Digest with {:?}", input);
    let output = p1.buffer();
    match ctx.op.do_final(input, output) {
        Err(e) => Err(e),
        Ok(hash_length) => {
            p2.set_a(hash_length as u32);
            Ok(())
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
