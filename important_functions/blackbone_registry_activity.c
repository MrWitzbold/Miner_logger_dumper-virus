
void __fastcall blackbone_registry_editor(int param_1,int param_2,int param_3)

{
  undefined4 *puVar1;
  int changed_key;
  byte *key_bytes_incremented;
  int extraout_EDX;
  int extraout_EDX_00;
  int extraout_EDX_01;
  int extraout_EDX_02;
  int mod_key;
  uint some_startend_difference;
  undefined in_stack_fffffcd4;
  uint local_324;
  uint local_320 [130];
  byte key_bytes [268];
  uint local_c;
  byte backwards_counter;
  
  local_c = DAT_4b3ab370 ^ (uint)&stack0xfffffffc;
  some_startend_difference = param_3 - *(int *)(param_2 + 0x30);
  changed_key = change_registry_key(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                                    ,L"BuildLabEx",local_320,0x104);
  mod_key = extraout_EDX;
  if ((-1 < changed_key) &&
     (changed_key = RtlUnicodeToMultiByteN(key_bytes,0x104,(uint *)0x0,local_320,0x208),
     mod_key = extraout_EDX_00, -1 < changed_key)) {
    key_bytes_incremented = key_bytes;
    do {
      backwards_counter = *key_bytes_incremented;
      key_bytes_incremented = key_bytes_incremented + 1;
    } while (backwards_counter != 0);
    changed_key = FUN_4b2ee154(param_2,0x42,(undefined4 *)(param_2 + 0x58),key_bytes,
                               (size_t)(key_bytes_incremented + (1 - (int)(key_bytes + 1))),
                               some_startend_difference,&local_324);
    mod_key = extraout_EDX_01;
    if (changed_key < 0) goto LAB_4b2ee143;
    some_startend_difference = some_startend_difference - (local_324 + 7 & 0xfffffff8);
  }
  puVar1 = *(undefined4 **)(undefined4 *)(param_1 + 0x14c);
  while ((puVar1 != (undefined4 *)(param_1 + 0x14c) &&
         (changed_key = FUN_4b2ee154(param_2,0x40,(undefined4 *)(param_2 + 0x58),puVar1 + 5,
                                     puVar1[3] - 4,some_startend_difference,&local_324),
         mod_key = extraout_EDX_02, -1 < changed_key))) {
    puVar1 = (undefined4 *)*puVar1;
    some_startend_difference = some_startend_difference - (local_324 + 7 & 0xfffffff8);
    mod_key = param_2 + 0x58;
  }
LAB_4b2ee143:
  FUN_4b2f4b70(local_c ^ (uint)&stack0xfffffffc,mod_key,in_stack_fffffcd4);
  return;
}

