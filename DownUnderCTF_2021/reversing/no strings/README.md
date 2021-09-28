# no strings

> This binary contains a free flag. No strings attached, seriously!
> 
> Author: joseph#8210
> 
> [`nostrings`](nostrings)

## Analysis

### ghidra

```cpp
undefined8 main(void)

{
  size_t sVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  int local_6c;
  char local_68 [72];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  printf("flag? ");
  fgets(local_68,0x46,stdin);
  local_6c = 0;
  do {
    sVar1 = strlen(local_68);
    if (sVar1 - 1 <= (ulong)(long)local_6c) {
      puts("correct!");
      uVar2 = 0;
LAB_00101231:
      if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return uVar2;
    }
    if (local_68[local_6c] != flag[local_6c * 2]) {
      puts("wrong!");
      uVar2 = 0xffffffff;
      goto LAB_00101231;
    }
    local_6c = local_6c + 1;
  } while( true );
}
```

The code doesn't seem to give out the flag in anyway.

But the binary must contain the flag.

## Solution

In ghidra checking `.rodata` we see the flag.

![](/DownUnderCTF_2021/reversing/no%20strings/imgs/nostrings.png)

flag: `DUCTF{stringent_strings_string}`

