+++
title = "Fishing Planet name change profanity check"
date = "2023-08-05"
author = "Samanthaa"
cover = "img/fishing-planet.webp"
description = "The game **Fishing Planet** allows you to change your name, but the proanity check is **client-side** only and can easily be abused with a single hook."
+++

If we open **GameAssembly.dll** in IDA pro after running [Link text Here](https://github.com/Perfare/Il2CppDumper) to generate **ida_py3.py** we can search the list of functions and end up finding a function called **AbusiveWords::HasAbusiveWords**

# Function dissassembly sparing the functions code because we don't care about it

```cpp
char __fastcall HasAbusiveWords(__int64 a1, unsigned __int8 a2, __int64 a3, __int64 a4)
{
}
```

# Abusing it with a single hook

Because this check is ran **client-side** and the server never confirms the name contains no profanity we can just create a signature to the function and hook it, then we just return 0, considering this game lacks an `Anti-cheat` we can use any hooking library we choose, for this example i went with `MinHook`

`48 89 5C 24 10 48 89 6C 24 18 56 48 83 EC 20 80 3D ? ? ? ? ? 0F B6 EA 48 8B F1 75 37`

```cpp
namespace AbusiveWords__HasAbusiveWords
{
    typedef char(__fastcall* fn)(__int64 a1, unsigned __int8 a2, __int64 a3, __int64 a4);
    inline fn original;
    extern char __fastcall hooked(__int64 a1, unsigned __int8 a2, __int64 a3, __int64 a4);
}

char __fastcall AbusiveWords__HasAbusiveWords::hooked(__int64 a1, unsigned __int8 a2, __int64 a3, __int64 a4)
{
    return false;
}

void hook()
{
    if (MH_Initialize() != MH_OK)//initialize minhook
        return;

    uint64_t has_abusive_words = signature_scan::scan(x"GameAssembly.dll", "48 89 5C 24 10 48 89 6C 24 18 56 48 83 EC 20 80 3D ? ? ? ? ? 0F B6 EA 48 8B F1 75 37");//scan for the function using the signature we created earlier
    bool successfully_hooked = MH_CreateHook((LPVOID)has_abusive_words, &AbusiveWords__HasAbusiveWords::hooked, reinterpret_cast<LPVOID*>(&AbusiveWords__HasAbusiveWords::original)) == MH_OK;//create the hook and confirm it was created

    bool successfully_enabled = MH_EnableHook(MH_ALL_HOOKS) == MH_OK;
}
```