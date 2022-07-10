
void __fastcall LSASS_dump(int param_1,undefined4 registry_key)

{
  char string_from_dll;
  int ntmap_section;
  int *piVar3;
  undefined4 extraout_EDX;
  undefined4 reg_key_byte_shift;
  undefined4 extraout_EDX_00;
  uint extraout_EDX_01;
  uint extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 extraout_EDX_04;
  undefined4 extraout_EDX_05;
  undefined4 extraout_EDX_06;
  byte **modified_reg_key_pointer;
  uint some_string_counter;
  byte **mod_reg_key_pointer;
  undefined **ppuVar8;
  int *piVar9;
  int registry_key2;
  ulonglong registry_key_value;
  undefined8 modified_reg_key;
  undefined4 system_root_directory;
  undefined *alloc_regkey;
  int local_5d0;
  int local_5c8;
  undefined4 local_5c4;
  undefined4 local_5c0 [2];
  undefined4 root_dir;
  undefined *allocated_reg_key;
  undefined4 local_5b0;
  undefined4 local_5ac;
  undefined4 *sys_directory_pointer;
  undefined4 local_5a4;
  undefined4 local_5a0;
  undefined4 local_59c;
  byte *local_590 [256];
  short local_190 [64];
  undefined local_110 [260];
  uint local_c;
  uint *in_stack_fffffa24;
  int **increment1;
  byte *reg_key_byte1;
  uint *reg_key_byte2_size;
  
  local_c = DAT_4b3ab370 ^ (uint)&stack0xfffffa24;
  local_5c8 = param_1;
  if (((LdrpChildNtdll != '\0') || (param_1 == 0)) ||
     (_string_from_dll = RtlInitUnicodeStringEx(local_5c0,L"DelegatedNtdll"),
     registry_key = extraout_EDX, _string_from_dll < 0)) goto LAB_4b333707;
  registry_key_value = NtQueryValueKey();
  registry_key = (undefined4)(registry_key_value >> 0x20);
  if ((int)registry_key_value < 0) {
    if ((int)registry_key_value == -0x7ffffffb) {
      while (increment1 = *(int ***)(*(int *)(registry_key2 + 0x30) + 0x18),
            increment1 != (int **)0x0) {
        modified_reg_key =
             RtlAllocateHeap(increment1,unknown_function1 + 0x180000,in_stack_fffffa24);
        registry_key = (undefined4)((ulonglong)modified_reg_key >> 0x20);
        modified_reg_key_pointer = (byte **)modified_reg_key;
        if (modified_reg_key_pointer == (byte **)0x0) break;
        registry_key_value = NtQueryValueKey();
        mod_reg_key_pointer = modified_reg_key_pointer;
        if (-1 < (int)registry_key_value) goto LAB_4b3333bd;
        if ((int)registry_key_value != -0x7ffffffb) goto LAB_4b3334b5;
        RtlFreeHeap(*(int ***)(*(int *)(registry_key2 + 0x30) + 0x18),0,modified_reg_key_pointer);
        registry_key = extraout_EDX_00;
      }
      goto LAB_4b333707;
    }
  }
  else {
    modified_reg_key_pointer = (byte **)0x0;
    mod_reg_key_pointer = local_590;
LAB_4b3333bd:
    reg_key_byte_shift = (undefined4)(registry_key_value >> 0x20);
    reg_key_byte1 = mod_reg_key_pointer[1];
    if ((reg_key_byte1 == (byte *)0x3) || (reg_key_byte1 == &DAT_00000007)) {
      if (reg_key_byte1 != (byte *)0x1) goto LAB_4b3333e5;
      in_stack_fffffa24 = (uint *)mod_reg_key_pointer[2];
      if ((byte *)0x80 < mod_reg_key_pointer[2]) goto LAB_4b3334b0;
      reg_key_byte2_size = (uint *)mod_reg_key_pointer[2];
LAB_4b33347c:
      memcpy(local_190,mod_reg_key_pointer + 3,(size_t)reg_key_byte2_size);
      registry_key_value = registry_key_value & 0xffffffff | (ulonglong)extraout_EDX_01 << 0x20;
    }
    else {
      if (((reg_key_byte1 == &DAT_00000004) || (reg_key_byte1 == &DAT_0000000b)) ||
         (reg_key_byte1 != (byte *)0x1)) {
LAB_4b3333e5:
        registry_key_value = CONCAT44(reg_key_byte_shift,0xc0000024);
      }
      else {
        reg_key_byte2_size = (uint *)mod_reg_key_pointer[2];
        in_stack_fffffa24 = reg_key_byte2_size;
        if (reg_key_byte2_size < (uint *)0x81) goto LAB_4b33347c;
LAB_4b3334b0:
        registry_key_value = CONCAT44(reg_key_byte_shift,0x80000005);
      }
    }
LAB_4b3334b5:
    if (modified_reg_key_pointer != (byte **)0x0) {
      RtlFreeHeap(*(int ***)(*(int *)(registry_key2 + 0x30) + 0x18),0,modified_reg_key_pointer);
      registry_key_value = registry_key_value & 0xffffffff | (ulonglong)extraout_EDX_02 << 0x20;
    }
  }
  registry_key = (undefined4)(registry_key_value >> 0x20);
  if ((int)registry_key_value < 0) goto LAB_4b333707;
  system_root_directory = 0x1000000;
  alloc_regkey = local_110;
  RtlAppendUnicodeToString((ushort *)&system_root_directory,L"\\SystemRoot\\system32\\");
  RtlReplaceSystemDirectoryInPath((ushort *)&system_root_directory,1,0x14c,'\x01');
  _string_from_dll = RtlAppendUnicodeToString((ushort *)&system_root_directory,local_190);
  registry_key = extraout_EDX_03;
  if (_string_from_dll < 0) goto LAB_4b333707;
  local_5ac = 0;
  sys_directory_pointer = &system_root_directory;
  local_5a0 = 0;
  local_59c = 0;
  local_5b0 = 0x18;
  local_5a4 = 0x40;
  if ((*(uint *)(*(int *)(registry_key2 + 0x30) + 0x68) & 0x40000) != 0) {
    root_dir = system_root_directory;
    allocated_reg_key = alloc_regkey;
    NtSystemDebugControl();
  }
  modified_reg_key = NtOpenFile();
  registry_key = (undefined4)((ulonglong)modified_reg_key >> 0x20);
  if ((int)modified_reg_key < 0) goto LAB_4b333707;
  local_5d0 = 0;
  _string_from_dll = NtCreateSection();
  if (-1 < _string_from_dll) {
    _string_from_dll = *(int *)(registry_key2 + 0x18);
    reg_key_byte_shift = *(undefined4 *)(_string_from_dll + 0x14);
    *(undefined **)(_string_from_dll + 0x14) = alloc_regkey;
    local_5c4 = 0;
    ntmap_section = NtMapViewOfSection();
    *(undefined4 *)(_string_from_dll + 0x14) = reg_key_byte_shift;
    if (ntmap_section == 0x40000003) {
      FUN_4b3311f1(DAT_4b3a68d0);
    }
    piVar3 = RtlImageNtHeader(DAT_4b3a68d0);
    if (piVar3 == (int *)0x0) {
      _string_from_dll = -0x3fffff85;
    }
    else {
      some_string_counter = 0;
      ppuVar8 = &PTR_s_LdrInitializeThunk_4b2819c0;
      do {
        _string_from_dll = FUN_4b2a62b0(DAT_4b3a68d0,*ppuVar8,0,(uint *)ppuVar8[1]);
        if (_string_from_dll < 0) goto joined_r0x4b3336bc;
        some_string_counter = some_string_counter + 1;
        ppuVar8 = ppuVar8 + 2;
      } while (some_string_counter < 0xd);
      if (*DAT_4b3a69d0 == LdrSystemDllInitBlock) {
        piVar3 = &LdrSystemDllInitBlock;
        piVar9 = DAT_4b3a69d0;
        for (ntmap_section = 0x3c; ntmap_section != 0; ntmap_section = ntmap_section + -1) {
          *piVar9 = *piVar3;
          piVar3 = piVar3 + 1;
          piVar9 = piVar9 + 1;
        }
        *DAT_4b3a69c0 = 1;
        *DAT_4b3a6994 = RtlInterlockedPopEntrySList;
        *DAT_4b3a69a4 = RtlInitializeNtUserPfn;
        *DAT_4b3a69c8 = RtlResetNtUserPfn;
        *DAT_4b3a69b8 = RtlRetrieveNtUserPfn;
      }
      else {
        _string_from_dll = -0x3fffffa7;
      }
    }
  }
  goto LAB_4b3336c9;
joined_r0x4b3336bc:
  for (; some_string_counter != 0; some_string_counter = some_string_counter - 1) {
    *(undefined4 *)ppuVar8[1] = 0;
  }
LAB_4b3336c9:
  NtClose();
  registry_key = extraout_EDX_04;
  if (local_5d0 != 0) {
    NtClose();
    registry_key = extraout_EDX_05;
  }
  if ((_string_from_dll < 0) && (DAT_4b3a68d0 != (int *)0x0)) {
    NtUnmapViewOfSection();
    DAT_4b3a68d0 = (int *)0x0;
    registry_key = extraout_EDX_06;
  }
LAB_4b333707:
  FUN_4b2f4b70(local_c ^ (uint)&stack0xfffffa24,registry_key,(char)in_stack_fffffa24);
  return;
}

