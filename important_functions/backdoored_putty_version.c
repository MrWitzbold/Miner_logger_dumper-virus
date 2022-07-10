
/* WARNING: Removing unreachable block (ram,0x4b348f5a) */
/* WARNING: Removing unreachable block (ram,0x4b348f7e) */
/* WARNING: Removing unreachable block (ram,0x4b348f8d) */
/* WARNING: Could not reconcile some variable overlaps */

void __fastcall FUN_4b348d39(int param_1,byte *param_2,uint param_3,undefined4 *param_4)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  int access_token;
  undefined4 *puVar4;
  void *_Dst;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 uVar5;
  byte *pbVar6;
  uint uVar7;
  uint *_Size;
  int in_FS_OFFSET;
  wchar_t *pwVar8;
  undefined in_stack_fffff9e4;
  uint local_614;
  int local_610;
  int local_608;
  uint local_604;
  uint local_600;
  uint local_5fc;
  undefined4 local_5f8;
  undefined4 *local_5f4;
  byte **local_5f0;
  ushort local_5ec;
  undefined2 local_5ea;
  undefined2 *local_5e8;
  uint local_5e4;
  undefined4 local_5e0;
  int local_5dc;
  ushort local_5d8;
  byte *local_5d0;
  short *local_538;
  char local_534;
  wchar_t local_420 [260];
  wchar_t local_218 [262];
  uint local_c;
  
  local_c = DAT_4b3ab370 ^ (uint)&stack0xfffff9e4;
  pbVar6 = (byte *)0x0;
  local_5f0 = (byte **)0x0;
  local_610 = param_1;
  memset(local_420,0,0x208);
  memset(local_218,0,0x208);
  local_5e8 = &DAT_4b2856c4;
  local_5ec = 2;
  local_5ea = 4;
  uVar5 = extraout_EDX;
  if ((param_4 == (undefined4 *)0x0) || (local_610 == 0)) goto LAB_4b34924b;
  local_614 = param_3 & 1;
  local_604 = param_3 & 2;
  local_600 = param_3 & 8;
  *param_4 = 0;
  param_4[1] = 0;
  local_5fc = 0;
  local_5f8 = 0;
  local_5e4 = 0;
  local_5e0 = 0;
  bVar3 = false;
  bVar2 = true;
  local_608 = 0;
  if (param_2 == (byte *)0x0) {
    access_token = NtQueryInformationToken();
    if (-1 < access_token) goto LAB_4b348e16;
  }
  else {
    bVar3 = true;
    pbVar6 = param_2;
LAB_4b348e16:
    access_token = NtQueryInformationToken();
    if ((-1 < access_token) &&
       (((local_608 == 0 ||
         ((access_token = NtQueryInformationToken(), -1 < access_token &&
          (access_token = RtlConvertSidToUnicodeString((ushort *)&local_5e4,local_5d0,'\x01'),
          -1 < access_token)))) && (access_token = NtQueryInformationToken(), -1 < access_token))))
    {
      if (!bVar3) goto LAB_4b348edd;
      access_token = RtlGetAppContainerSidType((char *)pbVar6,&local_5dc);
      if (-1 < access_token) {
        if (local_5dc == 2) {
          access_token = RtlConvertSidToUnicodeString((ushort *)&local_5fc,pbVar6,'\x01');
          if (-1 < access_token) {
LAB_4b348edd:
            access_token = NtQueryInformationToken();
            if (-1 < access_token) {
              if (((local_608 != 0) || (bVar3)) ||
                 (puVar4 = RtlGetCurrentServiceSessionId(), local_5f4 != puVar4)) {
                bVar1 = false;
              }
              else {
                bVar1 = true;
              }
              if ((char)local_614 == '\0') {
                if (bVar1) {
                  pwVar8 = L"\\BaseNamedObjects";
LAB_4b34909b:
                  access_token = FUN_4b34774a(local_420,0x104,(int)pwVar8);
                }
                else {
                  access_token = FUN_4b34777f(local_420,0x104,L"%s\\%ld\\%s");
                }
              }
              else {
                if ((param_3 & 4) != 0) {
                  pwVar8 = L"AppContainerNamedObjects";
                  goto LAB_4b34909b;
                }
                access_token = FUN_4b34777f(local_420,0x104,L"Global\\Session\\%ld%s");
              }
              if (-1 < access_token) {
                local_614 = 0;
                access_token = FUN_4b34770a(local_420,0x208,(int *)&local_614);
                if (-1 < access_token) {
                  uVar7 = local_614;
                  if ((local_608 != 0) && (local_604 == 0)) {
                    uVar7 = (local_5e4 & 0xffff) + 2 + local_614;
                  }
                  if (bVar3) {
                    uVar7 = uVar7 + (local_5fc & 0xffff) + 2;
                  }
                  if ((local_534 != '\0') && (local_600 == 0)) {
                    RtlInitUnicodeString((undefined4 *)&local_5d8,local_538);
                    uVar7 = uVar7 + local_5d8 + 2;
                  }
                  _Size = (uint *)(uVar7 + 2);
                  _Dst = (void *)FUN_4b2c5d70(_Size);
                  if (_Dst == (void *)0x0) {
                    access_token = -0x3fffff66;
                  }
                  else {
                    memset(_Dst,0,(size_t)_Size);
                    *param_4 = 0;
                    *(short *)((int)param_4 + 2) = (short)_Size;
                    param_4[1] = _Dst;
                    access_token = RtlAppendUnicodeToString((ushort *)param_4,local_420);
                    if ((((-1 < access_token) &&
                         (((local_608 == 0 || (local_604 != 0)) ||
                          ((access_token = RtlAppendUnicodeStringToString
                                                     ((ushort *)param_4,&local_5ec),
                           -1 < access_token &&
                           (access_token = RtlAppendUnicodeStringToString
                                                     ((ushort *)param_4,(ushort *)&local_5e4),
                           -1 < access_token)))))) &&
                        ((!bVar3 ||
                         ((access_token = RtlAppendUnicodeStringToString
                                                    ((ushort *)param_4,&local_5ec),
                          -1 < access_token &&
                          (access_token = RtlAppendUnicodeStringToString
                                                    ((ushort *)param_4,(ushort *)&local_5fc),
                          -1 < access_token)))))) &&
                       ((local_534 != '\0' &&
                        ((local_600 == 0 &&
                         (access_token = RtlAppendUnicodeStringToString
                                                   ((ushort *)param_4,&local_5ec), -1 < access_token
                         )))))) {
                      access_token = RtlAppendUnicodeStringToString((ushort *)param_4,&local_5d8);
                    }
                  }
                }
              }
            }
          }
        }
        else {
          access_token = RtlGetAppContainerParent((char *)pbVar6,(byte **)&local_5f0);
          if (((-1 < access_token) &&
              (access_token = RtlConvertSidToUnicodeString
                                        ((ushort *)&local_5fc,(byte *)local_5f0,'\x01'),
              -1 < access_token)) &&
             (access_token = FUN_4b34777f(local_218,0x104,L"%s\\%u-%u-%u-%u"), -1 < access_token)) {
            RtlFreeAnsiString(&local_5fc);
            RtlInitUnicodeString(&local_5fc,local_218);
            bVar2 = false;
            goto LAB_4b348edd;
          }
        }
      }
    }
  }
  RtlFreeAnsiString(&local_5e4);
  uVar5 = extraout_EDX_00;
  if (access_token < 0) {
    RtlFreeAnsiString(param_4);
    uVar5 = extraout_EDX_01;
  }
  if (bVar2) {
    RtlFreeAnsiString(&local_5fc);
    uVar5 = extraout_EDX_02;
  }
  if (local_5f0 != (byte **)0x0) {
    RtlFreeHeap(*(int ***)(*(int *)(in_FS_OFFSET + 0x30) + 0x18),0,local_5f0);
    uVar5 = extraout_EDX_03;
  }
LAB_4b34924b:
  FUN_4b2f4b70(local_c ^ (uint)&stack0xfffff9e4,uVar5,in_stack_fffff9e4);
  return;
}

