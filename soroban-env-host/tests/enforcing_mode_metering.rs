// Integration tests link the library without `cfg(test)`, so this file is
// compiled against whatever features `cargo test` enables. The expected budget
// values below must hold both with and without the `recording_mode` feature:
// compiling in recording mode support must not change what an enforcing-mode
// invocation is charged.

use expect_test::{expect, Expect};
use sha2::{Digest, Sha256};
use soroban_env_host::{
    budget::Budget,
    e2e_invoke::{entry_size_for_rent, invoke_host_function, TtlLedgerEntryMeta},
    meta::INTERFACE_VERSION,
    xdr::{
        AccountId, ContractCodeEntry, ContractCodeEntryExt, ContractDataDurability,
        ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint, HostFunction,
        InvokeContractArgs, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerFootprint,
        LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Limits, PublicKey, ScAddress,
        ScContractInstance, ScVal, SorobanResources, WriteXdr,
    },
    LedgerInfo,
};
use soroban_test_wasms::CONTRACT_STORAGE;

const LEDGER_SEQ: u32 = 1_000_000;

fn ledger_info() -> LedgerInfo {
    LedgerInfo {
        protocol_version: INTERFACE_VERSION.protocol,
        sequence_number: LEDGER_SEQ,
        timestamp: 12345678,
        network_id: [5; 32],
        base_reserve: 5_000_000,
        min_temp_entry_ttl: 16,
        min_persistent_entry_ttl: 100_000,
        max_entry_ttl: 10_000_000,
    }
}

fn ledger_entry(data: LedgerEntryData) -> LedgerEntry {
    LedgerEntry {
        last_modified_ledger_seq: 0,
        data,
        ext: LedgerEntryExt::V0,
    }
}

fn contract_data_key(contract: &ScAddress, key: ScVal) -> LedgerKey {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract.clone(),
        key,
        durability: ContractDataDurability::Persistent,
    })
}

struct Contract {
    address: ScAddress,
    wasm_key: LedgerKey,
    wasm_entry: LedgerEntry,
    instance_key: LedgerKey,
    instance_entry: LedgerEntry,
}

impl Contract {
    fn new(wasm: &[u8]) -> Self {
        let wasm_hash: [u8; 32] = Sha256::digest(wasm).into();
        let address = ScAddress::Contract(ContractId([111; 32].into()));
        let executable = ContractExecutable::Wasm(wasm_hash.into());
        Self {
            wasm_key: LedgerKey::ContractCode(LedgerKeyContractCode {
                hash: wasm_hash.into(),
            }),
            wasm_entry: ledger_entry(LedgerEntryData::ContractCode(ContractCodeEntry {
                ext: ContractCodeEntryExt::V0,
                hash: wasm_hash.into(),
                code: wasm.try_into().unwrap(),
            })),
            instance_key: contract_data_key(&address, ScVal::LedgerKeyContractInstance),
            instance_entry: ledger_entry(LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: address.clone(),
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
                val: ScVal::ContractInstance(ScContractInstance {
                    executable,
                    storage: None,
                }),
            })),
            address,
        }
    }

    fn call(&self, fn_name: &str, args: Vec<ScVal>) -> HostFunction {
        HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: self.address.clone(),
            function_name: fn_name.try_into().unwrap(),
            args: args.try_into().unwrap(),
        })
    }
}

// Runs `host_fn` through the enforcing-mode e2e entry point and checks the
// CPU and memory it was charged.
fn check_enforcing_budget(
    host_fn: HostFunction,
    read_only: Vec<LedgerKey>,
    read_write: Vec<LedgerKey>,
    entries: Vec<(LedgerEntry, u32)>,
    expected_cpu: Expect,
    expected_mem: Expect,
) {
    let resources = SorobanResources {
        footprint: LedgerFootprint {
            read_only: read_only.try_into().unwrap(),
            read_write: read_write.try_into().unwrap(),
        },
        instructions: 100_000_000,
        disk_read_bytes: 0,
        write_bytes: 0,
    };
    let footprint_keys: Vec<&LedgerKey> = resources
        .footprint
        .read_only
        .iter()
        .chain(resources.footprint.read_write.iter())
        .collect();
    let encoded_entries: Vec<(Option<Vec<u8>>, Option<TtlLedgerEntryMeta>)> = footprint_keys
        .into_iter()
        .map(|key| {
            entries
                .iter()
                .find(|(entry, _)| &ledger_entry_key(entry) == key)
                .map_or((None, None), |(entry, live_until_ledger)| {
                    let encoded = entry.to_xdr(Limits::none()).unwrap();
                    let entry_size_for_rent =
                        entry_size_for_rent(&Budget::default(), entry, encoded.len() as u32)
                            .unwrap();
                    (
                        Some(encoded),
                        Some(TtlLedgerEntryMeta {
                            live_until_ledger: *live_until_ledger,
                            entry_size_for_rent,
                        }),
                    )
                })
        })
        .collect();
    let source_account = AccountId(PublicKey::PublicKeyTypeEd25519([123; 32].into()));
    let budget = Budget::default();
    let res = invoke_host_function(
        &budget,
        false,
        host_fn.to_xdr(Limits::none()).unwrap(),
        resources.to_xdr(Limits::none()).unwrap(),
        &[],
        source_account.to_xdr(Limits::none()).unwrap(),
        Vec::<Vec<u8>>::new().into_iter(),
        ledger_info(),
        encoded_entries.into_iter(),
        vec![0; 32],
        &mut vec![],
        None,
        None,
    )
    .unwrap();
    assert!(res.encoded_invoke_result.is_ok());
    expected_cpu.assert_eq(&budget.get_cpu_insns_consumed().unwrap().to_string());
    expected_mem.assert_eq(&budget.get_mem_bytes_consumed().unwrap().to_string());
}

fn ledger_entry_key(entry: &LedgerEntry) -> LedgerKey {
    match &entry.data {
        LedgerEntryData::ContractCode(code) => LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: code.hash.clone(),
        }),
        LedgerEntryData::ContractData(data) => LedgerKey::ContractData(LedgerKeyContractData {
            contract: data.contract.clone(),
            key: data.key.clone(),
            durability: data.durability,
        }),
        _ => unreachable!(),
    }
}

#[test]
fn enforcing_mode_write_budget_does_not_depend_on_recording_mode_feature() {
    let contract = Contract::new(CONTRACT_STORAGE);
    let key = ScVal::Symbol("key".try_into().unwrap());
    let data_key = contract_data_key(&contract.address, key.clone());
    let data_entry = ledger_entry(LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract.address.clone(),
        key: key.clone(),
        durability: ContractDataDurability::Persistent,
        val: ScVal::U64(1),
    }));
    check_enforcing_budget(
        contract.call("put_persistent", vec![key, ScVal::U64(u64::MAX)]),
        vec![contract.instance_key.clone(), contract.wasm_key.clone()],
        vec![data_key],
        vec![
            (contract.wasm_entry.clone(), LEDGER_SEQ + 1000),
            (contract.instance_entry.clone(), LEDGER_SEQ + 1000),
            (data_entry, LEDGER_SEQ + 1000),
        ],
        expect!["1852923"],
        expect!["1414495"],
    );
}

#[test]
fn enforcing_mode_extend_ttl_budget_does_not_depend_on_recording_mode_feature() {
    let contract = Contract::new(CONTRACT_STORAGE);
    let key = ScVal::Symbol("key".try_into().unwrap());
    let data_key = contract_data_key(&contract.address, key.clone());
    let data_entry = ledger_entry(LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract.address.clone(),
        key: key.clone(),
        durability: ContractDataDurability::Persistent,
        val: ScVal::U64(1),
    }));
    check_enforcing_budget(
        contract.call(
            "extend_persistent",
            vec![key, ScVal::U32(200_000), ScVal::U32(300_000)],
        ),
        vec![
            contract.instance_key.clone(),
            contract.wasm_key.clone(),
            data_key,
        ],
        vec![],
        vec![
            (contract.wasm_entry.clone(), LEDGER_SEQ + 1000),
            (contract.instance_entry.clone(), LEDGER_SEQ + 1000),
            (data_entry, LEDGER_SEQ + 1000),
        ],
        expect!["1839848"],
        expect!["1413428"],
    );
}
