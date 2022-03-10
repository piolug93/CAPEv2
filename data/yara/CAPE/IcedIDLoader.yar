rule IcedIDLoader
{
    meta:
        author = "kevoreilly, threathive, enzo"
        description = "IcedID Loader"
        cape_type = "IcedID Loader"
    strings:
        $crypt1 = {8A 04 ?? D1 C? F7 D? D1 C? 81 E? 20 01 00 00 D1 C? F7 D? 81 E? 01 91 00 00 32 C? 88}
        $crypt2 = {8B 44 24 04 D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 C3}
        $crypt3 = {41 00 8B C8 C1 E1 08 0F B6 C4 66 33 C8 66 89 4? 24 A1 ?? ?? 41 00 89 4? 20 A0 ?? ?? 41 00 D0 E8 32 4? 32}
        $crypt4 = {0F B6 C8 [0-3] 8B C1 83 E1 0F [0-1] C1 E8 04 [0-1] 0F BE [2-5] 66 [0-1] 89 04 [1-2] 0F BE [2-5] 66 [0-1] 89 44 [2-3] 83 [4-5] 84 C0 75}
        $crypt5 = {48 C1 E8 04 0F BE 44 05 ?? 66 89 04 5E 44 88 75 E4 C7 45 E8 24 8F 6C 58 C7 45 EC 20 8B 68 5C C7 45 F0 2C 87 1F 29 C7 45 F4 57 FA 1B 2D}
        $download1 = {8D 44 24 40 50 8D 84 24 44 03 00 00 68 04 21 40 00 50 FF D5 8D 84 24 4C 01 00 00 C7 44 24 28 01 00 00 00 89 44 24 1C 8D 4C 24 1C 8D 84 24 4C 03 00 00 83 C4 0C 89 44 24 14 8B D3 B8 BB 01 00 00 66 89 44 24 18 57}
        $download2 = {8B 75 ?? 8D 4D ?? 8B 7D ?? 8B D6 57 89 1E 89 1F E8 [4] 59 3D C8 00 00 00 75 05 33 C0 40 EB}
        $download3 = {B8 50 00 00 00 66 89 45 ?? 4C 89 65 ?? 4C 89 75 ?? E8 [4] 48 8B 1E 3D 94 01 00 00}
        $major_ver = {0F B6 05 ?? ?? ?? ?? 6A ?? 6A 72 FF 75 0C 6A 70 50 FF 35 ?? ?? ?? ?? 8D 45 80 FF 35 ?? ?? ?? ?? 6A 63 FF 75 08 6A 67 50 FF 75 10 FF 15 ?? ?? ?? ?? 83 C4 38 8B E5 5D C3}
        $decode = {4? 8D [5-6] 8A 4? [1-3] 32 }//0? 01 88 44 [2] 4?}
    condition:
        2 of them
}
