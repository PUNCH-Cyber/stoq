/*
   Copyright 2014-2015 PUNCH Cyber Analytics Group

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

rule swf_file
{
    meta:
        plugin = "carver:swf"
        save = "True"
    strings:
        $cws = "CWS"
        $fws = "FWS"
        $zws = "ZWS"
    condition:
        any of them
}

rule xdp_file
{
    meta:
        plugin = "carver:xdp"
        save = "True"
    strings:
        $xdp = "xdp:xdp"
        $pdf = "<pdf "
    condition:
        all of them
}

rule ole_file
{
    meta:
        plugin = "carver:ole"
        save = "False"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
    condition:
        $ole
}

rule rtf_file
{
    meta:
        plugin = "carver:rtf"
        save = "True"
    strings:
        $rtf = "{\\rt" nocase
    condition:
        $rtf at 0
}

rule exe_file
{
    meta:
        plugin = "carver:pe"
        save = "True"
    strings:
        $MZ = "MZ"
        $ZM = "ZM"
        $dos_stub = "This program cannot be run in DOS mode"
        $win32_stub = "This program must be run under Win32"
    condition:
        ($MZ or $ZM) and ($dos_stub or $win32_stub) in (1..filesize)
}

rule zip_file
{
    meta:
        plugin = "extractor:decompress"
        save = "True"
    strings:
        $zip = { 50 4b 05 06 }
        $zip1 = { 50 4b 03 04 }
        $zip2 = { 50 4b 07 08 }
    condition:
        ($zip at 0) or ($zip1 at 0) or ($zip2 at 0)
}

rule ace_file
{
    meta:
        plugin = "extractor:decompress"
        save = "True"
    strings:
        // **ACE**
        $magic = { 2a 2a 41 43 45 2a 2a }
    condition:
        $magic at 7
}

rule xor_This_program_key_1
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "1"
    strings:
        $xord_1 = { 55 69 68 72 21 71 73 6e 66 73 60 6c }
    condition:
        any of them
}

rule xor_This_program_key_2
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "2"
    strings:
        $xord_2 = { 56 6a 6b 71 22 72 70 6d 65 70 63 6f }
    condition:
        any of them
}

rule xor_This_program_key_3
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "3"
    strings:
        $xord_3 = { 57 6b 6a 70 23 73 71 6c 64 71 62 6e }
    condition:
        any of them
}

rule xor_This_program_key_4
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "4"
    strings:
        $xord_4 = { 50 6c 6d 77 24 74 76 6b 63 76 65 69 }
    condition:
        any of them
}

rule xor_This_program_key_5
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "5"
    strings:
        $xord_5 = { 51 6d 6c 76 25 75 77 6a 62 77 64 68 }
    condition:
        any of them
}

rule xor_This_program_key_6
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "6"
    strings:
        $xord_6 = { 52 6e 6f 75 26 76 74 69 61 74 67 6b }
    condition:
        any of them
}

rule xor_This_program_key_7
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "7"
    strings:
        $xord_7 = { 53 6f 6e 74 27 77 75 68 60 75 66 6a }
    condition:
        any of them
}

rule xor_This_program_key_8
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "8"
    strings:
        $xord_8 = { 5c 60 61 7b 28 78 7a 67 6f 7a 69 65 }
    condition:
        any of them
}

rule xor_This_program_key_9
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "9"
    strings:
        $xord_9 = { 5d 61 60 7a 29 79 7b 66 6e 7b 68 64 }
    condition:
        any of them
}

rule xor_This_program_key_10
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "10"
    strings:
        $xord_10 = { 5e 62 63 79 2a 7a 78 65 6d 78 6b 67 }
    condition:
        any of them
}

rule xor_This_program_key_11
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "11"
    strings:
        $xord_11 = { 5f 63 62 78 2b 7b 79 64 6c 79 6a 66 }
    condition:
        any of them
}

rule xor_This_program_key_12
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "12"
    strings:
        $xord_12 = { 58 64 65 7f 2c 7c 7e 63 6b 7e 6d 61 }
    condition:
        any of them
}

rule xor_This_program_key_13
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "13"
    strings:
        $xord_13 = { 59 65 64 7e 2d 7d 7f 62 6a 7f 6c 60 }
    condition:
        any of them
}

rule xor_This_program_key_14
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "14"
    strings:
        $xord_14 = { 5a 66 67 7d 2e 7e 7c 61 69 7c 6f 63 }
    condition:
        any of them
}

rule xor_This_program_key_15
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "15"
    strings:
        $xord_15 = { 5b 67 66 7c 2f 7f 7d 60 68 7d 6e 62 }
    condition:
        any of them
}

rule xor_This_program_key_16
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "16"
    strings:
        $xord_16 = { 44 78 79 63 30 60 62 7f 77 62 71 7d }
    condition:
        any of them
}

rule xor_This_program_key_17
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "17"
    strings:
        $xord_17 = { 45 79 78 62 31 61 63 7e 76 63 70 7c }
    condition:
        any of them
}

rule xor_This_program_key_18
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "18"
    strings:
        $xord_18 = { 46 7a 7b 61 32 62 60 7d 75 60 73 7f }
    condition:
        any of them
}

rule xor_This_program_key_19
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "19"
    strings:
        $xord_19 = { 47 7b 7a 60 33 63 61 7c 74 61 72 7e }
    condition:
        any of them
}

rule xor_This_program_key_20
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "20"
    strings:
        $xord_20 = { 40 7c 7d 67 34 64 66 7b 73 66 75 79 }
    condition:
        any of them
}

rule xor_This_program_key_21
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "21"
    strings:
        $xord_21 = { 41 7d 7c 66 35 65 67 7a 72 67 74 78 }
    condition:
        any of them
}

rule xor_This_program_key_22
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "22"
    strings:
        $xord_22 = { 42 7e 7f 65 36 66 64 79 71 64 77 7b }
    condition:
        any of them
}

rule xor_This_program_key_23
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "23"
    strings:
        $xord_23 = { 43 7f 7e 64 37 67 65 78 70 65 76 7a }
    condition:
        any of them
}

rule xor_This_program_key_24
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "24"
    strings:
        $xord_24 = { 4c 70 71 6b 38 68 6a 77 7f 6a 79 75 }
    condition:
        any of them
}

rule xor_This_program_key_25
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "25"
    strings:
        $xord_25 = { 4d 71 70 6a 39 69 6b 76 7e 6b 78 74 }
    condition:
        any of them
}

rule xor_This_program_key_26
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "26"
    strings:
        $xord_26 = { 4e 72 73 69 3a 6a 68 75 7d 68 7b 77 }
    condition:
        any of them
}

rule xor_This_program_key_27
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "27"
    strings:
        $xord_27 = { 4f 73 72 68 3b 6b 69 74 7c 69 7a 76 }
    condition:
        any of them
}

rule xor_This_program_key_28
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "28"
    strings:
        $xord_28 = { 48 74 75 6f 3c 6c 6e 73 7b 6e 7d 71 }
    condition:
        any of them
}

rule xor_This_program_key_29
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "29"
    strings:
        $xord_29 = { 49 75 74 6e 3d 6d 6f 72 7a 6f 7c 70 }
    condition:
        any of them
}

rule xor_This_program_key_30
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "30"
    strings:
        $xord_30 = { 4a 76 77 6d 3e 6e 6c 71 79 6c 7f 73 }
    condition:
        any of them
}

rule xor_This_program_key_31
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "31"
    strings:
        $xord_31 = { 4b 77 76 6c 3f 6f 6d 70 78 6d 7e 72 }
    condition:
        any of them
}

rule xor_This_program_key_32
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "32"
    strings:
        $xord_32 = { 74 48 49 53 00 50 52 4f 47 52 41 4d }
    condition:
        any of them
}

rule xor_This_program_key_33
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "33"
    strings:
        $xord_33 = { 75 49 48 52 01 51 53 4e 46 53 40 4c }
    condition:
        any of them
}

rule xor_This_program_key_34
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "34"
    strings:
        $xord_34 = { 76 4a 4b 51 02 52 50 4d 45 50 43 4f }
    condition:
        any of them
}

rule xor_This_program_key_35
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "35"
    strings:
        $xord_35 = { 77 4b 4a 50 03 53 51 4c 44 51 42 4e }
    condition:
        any of them
}

rule xor_This_program_key_36
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "36"
    strings:
        $xord_36 = { 70 4c 4d 57 04 54 56 4b 43 56 45 49 }
    condition:
        any of them
}

rule xor_This_program_key_37
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "37"
    strings:
        $xord_37 = { 71 4d 4c 56 05 55 57 4a 42 57 44 48 }
    condition:
        any of them
}

rule xor_This_program_key_38
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "38"
    strings:
        $xord_38 = { 72 4e 4f 55 06 56 54 49 41 54 47 4b }
    condition:
        any of them
}

rule xor_This_program_key_39
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "39"
    strings:
        $xord_39 = { 73 4f 4e 54 07 57 55 48 40 55 46 4a }
    condition:
        any of them
}

rule xor_This_program_key_40
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "40"
    strings:
        $xord_40 = { 7c 40 41 5b 08 58 5a 47 4f 5a 49 45 }
    condition:
        any of them
}

rule xor_This_program_key_41
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "41"
    strings:
        $xord_41 = { 7d 41 40 5a 09 59 5b 46 4e 5b 48 44 }
    condition:
        any of them
}

rule xor_This_program_key_42
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "42"
    strings:
        $xord_42 = { 7e 42 43 59 0a 5a 58 45 4d 58 4b 47 }
    condition:
        any of them
}

rule xor_This_program_key_43
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "43"
    strings:
        $xord_43 = { 7f 43 42 58 0b 5b 59 44 4c 59 4a 46 }
    condition:
        any of them
}

rule xor_This_program_key_44
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "44"
    strings:
        $xord_44 = { 78 44 45 5f 0c 5c 5e 43 4b 5e 4d 41 }
    condition:
        any of them
}

rule xor_This_program_key_45
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "45"
    strings:
        $xord_45 = { 79 45 44 5e 0d 5d 5f 42 4a 5f 4c 40 }
    condition:
        any of them
}

rule xor_This_program_key_46
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "46"
    strings:
        $xord_46 = { 7a 46 47 5d 0e 5e 5c 41 49 5c 4f 43 }
    condition:
        any of them
}

rule xor_This_program_key_47
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "47"
    strings:
        $xord_47 = { 7b 47 46 5c 0f 5f 5d 40 48 5d 4e 42 }
    condition:
        any of them
}

rule xor_This_program_key_48
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "48"
    strings:
        $xord_48 = { 64 58 59 43 10 40 42 5f 57 42 51 5d }
    condition:
        any of them
}

rule xor_This_program_key_49
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "49"
    strings:
        $xord_49 = { 65 59 58 42 11 41 43 5e 56 43 50 5c }
    condition:
        any of them
}

rule xor_This_program_key_50
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "50"
    strings:
        $xord_50 = { 66 5a 5b 41 12 42 40 5d 55 40 53 5f }
    condition:
        any of them
}

rule xor_This_program_key_51
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "51"
    strings:
        $xord_51 = { 67 5b 5a 40 13 43 41 5c 54 41 52 5e }
    condition:
        any of them
}

rule xor_This_program_key_52
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "52"
    strings:
        $xord_52 = { 60 5c 5d 47 14 44 46 5b 53 46 55 59 }
    condition:
        any of them
}

rule xor_This_program_key_53
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "53"
    strings:
        $xord_53 = { 61 5d 5c 46 15 45 47 5a 52 47 54 58 }
    condition:
        any of them
}

rule xor_This_program_key_54
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "54"
    strings:
        $xord_54 = { 62 5e 5f 45 16 46 44 59 51 44 57 5b }
    condition:
        any of them
}

rule xor_This_program_key_55
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "55"
    strings:
        $xord_55 = { 63 5f 5e 44 17 47 45 58 50 45 56 5a }
    condition:
        any of them
}

rule xor_This_program_key_56
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "56"
    strings:
        $xord_56 = { 6c 50 51 4b 18 48 4a 57 5f 4a 59 55 }
    condition:
        any of them
}

rule xor_This_program_key_57
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "57"
    strings:
        $xord_57 = { 6d 51 50 4a 19 49 4b 56 5e 4b 58 54 }
    condition:
        any of them
}

rule xor_This_program_key_58
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "58"
    strings:
        $xord_58 = { 6e 52 53 49 1a 4a 48 55 5d 48 5b 57 }
    condition:
        any of them
}

rule xor_This_program_key_59
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "59"
    strings:
        $xord_59 = { 6f 53 52 48 1b 4b 49 54 5c 49 5a 56 }
    condition:
        any of them
}

rule xor_This_program_key_60
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "60"
    strings:
        $xord_60 = { 68 54 55 4f 1c 4c 4e 53 5b 4e 5d 51 }
    condition:
        any of them
}

rule xor_This_program_key_61
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "61"
    strings:
        $xord_61 = { 69 55 54 4e 1d 4d 4f 52 5a 4f 5c 50 }
    condition:
        any of them
}

rule xor_This_program_key_62
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "62"
    strings:
        $xord_62 = { 6a 56 57 4d 1e 4e 4c 51 59 4c 5f 53 }
    condition:
        any of them
}

rule xor_This_program_key_63
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "63"
    strings:
        $xord_63 = { 6b 57 56 4c 1f 4f 4d 50 58 4d 5e 52 }
    condition:
        any of them
}

rule xor_This_program_key_64
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "64"
    strings:
        $xord_64 = { 14 28 29 33 60 30 32 2f 27 32 21 2d }
    condition:
        any of them
}

rule xor_This_program_key_65
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "65"
    strings:
        $xord_65 = { 15 29 28 32 61 31 33 2e 26 33 20 2c }
    condition:
        any of them
}

rule xor_This_program_key_66
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "66"
    strings:
        $xord_66 = { 16 2a 2b 31 62 32 30 2d 25 30 23 2f }
    condition:
        any of them
}

rule xor_This_program_key_67
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "67"
    strings:
        $xord_67 = { 17 2b 2a 30 63 33 31 2c 24 31 22 2e }
    condition:
        any of them
}

rule xor_This_program_key_68
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "68"
    strings:
        $xord_68 = { 10 2c 2d 37 64 34 36 2b 23 36 25 29 }
    condition:
        any of them
}

rule xor_This_program_key_69
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "69"
    strings:
        $xord_69 = { 11 2d 2c 36 65 35 37 2a 22 37 24 28 }
    condition:
        any of them
}

rule xor_This_program_key_70
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "70"
    strings:
        $xord_70 = { 12 2e 2f 35 66 36 34 29 21 34 27 2b }
    condition:
        any of them
}

rule xor_This_program_key_71
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "71"
    strings:
        $xord_71 = { 13 2f 2e 34 67 37 35 28 20 35 26 2a }
    condition:
        any of them
}

rule xor_This_program_key_72
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "72"
    strings:
        $xord_72 = { 1c 20 21 3b 68 38 3a 27 2f 3a 29 25 }
    condition:
        any of them
}

rule xor_This_program_key_73
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "73"
    strings:
        $xord_73 = { 1d 21 20 3a 69 39 3b 26 2e 3b 28 24 }
    condition:
        any of them
}

rule xor_This_program_key_74
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "74"
    strings:
        $xord_74 = { 1e 22 23 39 6a 3a 38 25 2d 38 2b 27 }
    condition:
        any of them
}

rule xor_This_program_key_75
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "75"
    strings:
        $xord_75 = { 1f 23 22 38 6b 3b 39 24 2c 39 2a 26 }
    condition:
        any of them
}

rule xor_This_program_key_76
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "76"
    strings:
        $xord_76 = { 18 24 25 3f 6c 3c 3e 23 2b 3e 2d 21 }
    condition:
        any of them
}

rule xor_This_program_key_77
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "77"
    strings:
        $xord_77 = { 19 25 24 3e 6d 3d 3f 22 2a 3f 2c 20 }
    condition:
        any of them
}

rule xor_This_program_key_78
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "78"
    strings:
        $xord_78 = { 1a 26 27 3d 6e 3e 3c 21 29 3c 2f 23 }
    condition:
        any of them
}

rule xor_This_program_key_79
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "79"
    strings:
        $xord_79 = { 1b 27 26 3c 6f 3f 3d 20 28 3d 2e 22 }
    condition:
        any of them
}

rule xor_This_program_key_80
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "80"
    strings:
        $xord_80 = { 04 38 39 23 70 20 22 3f 37 22 31 3d }
    condition:
        any of them
}

rule xor_This_program_key_81
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "81"
    strings:
        $xord_81 = { 05 39 38 22 71 21 23 3e 36 23 30 3c }
    condition:
        any of them
}

rule xor_This_program_key_82
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "82"
    strings:
        $xord_82 = { 06 3a 3b 21 72 22 20 3d 35 20 33 3f }
    condition:
        any of them
}

rule xor_This_program_key_83
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "83"
    strings:
        $xord_83 = { 07 3b 3a 20 73 23 21 3c 34 21 32 3e }
    condition:
        any of them
}

rule xor_This_program_key_84
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "84"
    strings:
        $xord_84 = { 00 3c 3d 27 74 24 26 3b 33 26 35 39 }
    condition:
        any of them
}

rule xor_This_program_key_85
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "85"
    strings:
        $xord_85 = { 01 3d 3c 26 75 25 27 3a 32 27 34 38 }
    condition:
        any of them
}

rule xor_This_program_key_86
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "86"
    strings:
        $xord_86 = { 02 3e 3f 25 76 26 24 39 31 24 37 3b }
    condition:
        any of them
}

rule xor_This_program_key_87
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "87"
    strings:
        $xord_87 = { 03 3f 3e 24 77 27 25 38 30 25 36 3a }
    condition:
        any of them
}

rule xor_This_program_key_88
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "88"
    strings:
        $xord_88 = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 }
    condition:
        any of them
}

rule xor_This_program_key_89
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "89"
    strings:
        $xord_89 = { 0d 31 30 2a 79 29 2b 36 3e 2b 38 34 }
    condition:
        any of them
}

rule xor_This_program_key_90
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "90"
    strings:
        $xord_90 = { 0e 32 33 29 7a 2a 28 35 3d 28 3b 37 }
    condition:
        any of them
}

rule xor_This_program_key_91
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "91"
    strings:
        $xord_91 = { 0f 33 32 28 7b 2b 29 34 3c 29 3a 36 }
    condition:
        any of them
}

rule xor_This_program_key_92
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "92"
    strings:
        $xord_92 = { 08 34 35 2f 7c 2c 2e 33 3b 2e 3d 31 }
    condition:
        any of them
}

rule xor_This_program_key_93
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "93"
    strings:
        $xord_93 = { 09 35 34 2e 7d 2d 2f 32 3a 2f 3c 30 }
    condition:
        any of them
}

rule xor_This_program_key_94
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "94"
    strings:
        $xord_94 = { 0a 36 37 2d 7e 2e 2c 31 39 2c 3f 33 }
    condition:
        any of them
}

rule xor_This_program_key_95
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "95"
    strings:
        $xord_95 = { 0b 37 36 2c 7f 2f 2d 30 38 2d 3e 32 }
    condition:
        any of them
}

rule xor_This_program_key_96
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "96"
    strings:
        $xord_96 = { 34 08 09 13 40 10 12 0f 07 12 01 0d }
    condition:
        any of them
}

rule xor_This_program_key_97
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "97"
    strings:
        $xord_97 = { 35 09 08 12 41 11 13 0e 06 13 00 0c }
    condition:
        any of them
}

rule xor_This_program_key_98
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "98"
    strings:
        $xord_98 = { 36 0a 0b 11 42 12 10 0d 05 10 03 0f }
    condition:
        any of them
}

rule xor_This_program_key_99
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "99"
    strings:
        $xord_99 = { 37 0b 0a 10 43 13 11 0c 04 11 02 0e }
    condition:
        any of them
}

rule xor_This_program_key_100
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "100"
    strings:
        $xord_100 = { 30 0c 0d 17 44 14 16 0b 03 16 05 09 }
    condition:
        any of them
}

rule xor_This_program_key_101
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "101"
    strings:
        $xord_101 = { 31 0d 0c 16 45 15 17 0a 02 17 04 08 }
    condition:
        any of them
}

rule xor_This_program_key_102
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "102"
    strings:
        $xord_102 = { 32 0e 0f 15 46 16 14 09 01 14 07 0b }
    condition:
        any of them
}

rule xor_This_program_key_103
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "103"
    strings:
        $xord_103 = { 33 0f 0e 14 47 17 15 08 00 15 06 0a }
    condition:
        any of them
}

rule xor_This_program_key_104
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "104"
    strings:
        $xord_104 = { 3c 00 01 1b 48 18 1a 07 0f 1a 09 05 }
    condition:
        any of them
}

rule xor_This_program_key_105
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "105"
    strings:
        $xord_105 = { 3d 01 00 1a 49 19 1b 06 0e 1b 08 04 }
    condition:
        any of them
}

rule xor_This_program_key_106
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "106"
    strings:
        $xord_106 = { 3e 02 03 19 4a 1a 18 05 0d 18 0b 07 }
    condition:
        any of them
}

rule xor_This_program_key_107
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "107"
    strings:
        $xord_107 = { 3f 03 02 18 4b 1b 19 04 0c 19 0a 06 }
    condition:
        any of them
}

rule xor_This_program_key_108
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "108"
    strings:
        $xord_108 = { 38 04 05 1f 4c 1c 1e 03 0b 1e 0d 01 }
    condition:
        any of them
}

rule xor_This_program_key_109
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "109"
    strings:
        $xord_109 = { 39 05 04 1e 4d 1d 1f 02 0a 1f 0c 00 }
    condition:
        any of them
}

rule xor_This_program_key_110
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "110"
    strings:
        $xord_110 = { 3a 06 07 1d 4e 1e 1c 01 09 1c 0f 03 }
    condition:
        any of them
}

rule xor_This_program_key_111
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "111"
    strings:
        $xord_111 = { 3b 07 06 1c 4f 1f 1d 00 08 1d 0e 02 }
    condition:
        any of them
}

rule xor_This_program_key_112
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "112"
    strings:
        $xord_112 = { 24 18 19 03 50 00 02 1f 17 02 11 1d }
    condition:
        any of them
}

rule xor_This_program_key_113
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "113"
    strings:
        $xord_113 = { 25 19 18 02 51 01 03 1e 16 03 10 1c }
    condition:
        any of them
}

rule xor_This_program_key_114
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "114"
    strings:
        $xord_114 = { 26 1a 1b 01 52 02 00 1d 15 00 13 1f }
    condition:
        any of them
}

rule xor_This_program_key_115
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "115"
    strings:
        $xord_115 = { 27 1b 1a 00 53 03 01 1c 14 01 12 1e }
    condition:
        any of them
}

rule xor_This_program_key_116
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "116"
    strings:
        $xord_116 = { 20 1c 1d 07 54 04 06 1b 13 06 15 19 }
    condition:
        any of them
}

rule xor_This_program_key_117
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "117"
    strings:
        $xord_117 = { 21 1d 1c 06 55 05 07 1a 12 07 14 18 }
    condition:
        any of them
}

rule xor_This_program_key_118
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "118"
    strings:
        $xord_118 = { 22 1e 1f 05 56 06 04 19 11 04 17 1b }
    condition:
        any of them
}

rule xor_This_program_key_119
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "119"
    strings:
        $xord_119 = { 23 1f 1e 04 57 07 05 18 10 05 16 1a }
    condition:
        any of them
}

rule xor_This_program_key_120
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "120"
    strings:
        $xord_120 = { 2c 10 11 0b 58 08 0a 17 1f 0a 19 15 }
    condition:
        any of them
}

rule xor_This_program_key_121
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "121"
    strings:
        $xord_121 = { 2d 11 10 0a 59 09 0b 16 1e 0b 18 14 }
    condition:
        any of them
}

rule xor_This_program_key_122
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "122"
    strings:
        $xord_122 = { 2e 12 13 09 5a 0a 08 15 1d 08 1b 17 }
    condition:
        any of them
}

rule xor_This_program_key_123
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "123"
    strings:
        $xord_123 = { 2f 13 12 08 5b 0b 09 14 1c 09 1a 16 }
    condition:
        any of them
}

rule xor_This_program_key_124
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "124"
    strings:
        $xord_124 = { 28 14 15 0f 5c 0c 0e 13 1b 0e 1d 11 }
    condition:
        any of them
}

rule xor_This_program_key_125
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "125"
    strings:
        $xord_125 = { 29 15 14 0e 5d 0d 0f 12 1a 0f 1c 10 }
    condition:
        any of them
}

rule xor_This_program_key_126
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "126"
    strings:
        $xord_126 = { 2a 16 17 0d 5e 0e 0c 11 19 0c 1f 13 }
    condition:
        any of them
}

rule xor_This_program_key_127
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "127"
    strings:
        $xord_127 = { 2b 17 16 0c 5f 0f 0d 10 18 0d 1e 12 }
    condition:
        any of them
}

rule xor_This_program_key_128
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "128"
    strings:
        $xord_128 = { d4 e8 e9 f3 a0 f0 f2 ef e7 f2 e1 ed }
    condition:
        any of them
}

rule xor_This_program_key_129
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "129"
    strings:
        $xord_129 = { d5 e9 e8 f2 a1 f1 f3 ee e6 f3 e0 ec }
    condition:
        any of them
}

rule xor_This_program_key_130
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "130"
    strings:
        $xord_130 = { d6 ea eb f1 a2 f2 f0 ed e5 f0 e3 ef }
    condition:
        any of them
}

rule xor_This_program_key_131
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "131"
    strings:
        $xord_131 = { d7 eb ea f0 a3 f3 f1 ec e4 f1 e2 ee }
    condition:
        any of them
}

rule xor_This_program_key_132
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "132"
    strings:
        $xord_132 = { d0 ec ed f7 a4 f4 f6 eb e3 f6 e5 e9 }
    condition:
        any of them
}

rule xor_This_program_key_133
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "133"
    strings:
        $xord_133 = { d1 ed ec f6 a5 f5 f7 ea e2 f7 e4 e8 }
    condition:
        any of them
}

rule xor_This_program_key_134
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "134"
    strings:
        $xord_134 = { d2 ee ef f5 a6 f6 f4 e9 e1 f4 e7 eb }
    condition:
        any of them
}

rule xor_This_program_key_135
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "135"
    strings:
        $xord_135 = { d3 ef ee f4 a7 f7 f5 e8 e0 f5 e6 ea }
    condition:
        any of them
}

rule xor_This_program_key_136
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "136"
    strings:
        $xord_136 = { dc e0 e1 fb a8 f8 fa e7 ef fa e9 e5 }
    condition:
        any of them
}

rule xor_This_program_key_137
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "137"
    strings:
        $xord_137 = { dd e1 e0 fa a9 f9 fb e6 ee fb e8 e4 }
    condition:
        any of them
}

rule xor_This_program_key_138
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "138"
    strings:
        $xord_138 = { de e2 e3 f9 aa fa f8 e5 ed f8 eb e7 }
    condition:
        any of them
}

rule xor_This_program_key_139
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "139"
    strings:
        $xord_139 = { df e3 e2 f8 ab fb f9 e4 ec f9 ea e6 }
    condition:
        any of them
}

rule xor_This_program_key_140
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "140"
    strings:
        $xord_140 = { d8 e4 e5 ff ac fc fe e3 eb fe ed e1 }
    condition:
        any of them
}

rule xor_This_program_key_141
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "141"
    strings:
        $xord_141 = { d9 e5 e4 fe ad fd ff e2 ea ff ec e0 }
    condition:
        any of them
}

rule xor_This_program_key_142
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "142"
    strings:
        $xord_142 = { da e6 e7 fd ae fe fc e1 e9 fc ef e3 }
    condition:
        any of them
}

rule xor_This_program_key_143
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "143"
    strings:
        $xord_143 = { db e7 e6 fc af ff fd e0 e8 fd ee e2 }
    condition:
        any of them
}

rule xor_This_program_key_144
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "144"
    strings:
        $xord_144 = { c4 f8 f9 e3 b0 e0 e2 ff f7 e2 f1 fd }
    condition:
        any of them
}

rule xor_This_program_key_145
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "145"
    strings:
        $xord_145 = { c5 f9 f8 e2 b1 e1 e3 fe f6 e3 f0 fc }
    condition:
        any of them
}

rule xor_This_program_key_146
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "146"
    strings:
        $xord_146 = { c6 fa fb e1 b2 e2 e0 fd f5 e0 f3 ff }
    condition:
        any of them
}

rule xor_This_program_key_147
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "147"
    strings:
        $xord_147 = { c7 fb fa e0 b3 e3 e1 fc f4 e1 f2 fe }
    condition:
        any of them
}

rule xor_This_program_key_148
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "148"
    strings:
        $xord_148 = { c0 fc fd e7 b4 e4 e6 fb f3 e6 f5 f9 }
    condition:
        any of them
}

rule xor_This_program_key_149
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "149"
    strings:
        $xord_149 = { c1 fd fc e6 b5 e5 e7 fa f2 e7 f4 f8 }
    condition:
        any of them
}

rule xor_This_program_key_150
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "150"
    strings:
        $xord_150 = { c2 fe ff e5 b6 e6 e4 f9 f1 e4 f7 fb }
    condition:
        any of them
}

rule xor_This_program_key_151
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "151"
    strings:
        $xord_151 = { c3 ff fe e4 b7 e7 e5 f8 f0 e5 f6 fa }
    condition:
        any of them
}

rule xor_This_program_key_152
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "152"
    strings:
        $xord_152 = { cc f0 f1 eb b8 e8 ea f7 ff ea f9 f5 }
    condition:
        any of them
}

rule xor_This_program_key_153
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "153"
    strings:
        $xord_153 = { cd f1 f0 ea b9 e9 eb f6 fe eb f8 f4 }
    condition:
        any of them
}

rule xor_This_program_key_154
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "154"
    strings:
        $xord_154 = { ce f2 f3 e9 ba ea e8 f5 fd e8 fb f7 }
    condition:
        any of them
}

rule xor_This_program_key_155
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "155"
    strings:
        $xord_155 = { cf f3 f2 e8 bb eb e9 f4 fc e9 fa f6 }
    condition:
        any of them
}

rule xor_This_program_key_156
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "156"
    strings:
        $xord_156 = { c8 f4 f5 ef bc ec ee f3 fb ee fd f1 }
    condition:
        any of them
}

rule xor_This_program_key_157
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "157"
    strings:
        $xord_157 = { c9 f5 f4 ee bd ed ef f2 fa ef fc f0 }
    condition:
        any of them
}

rule xor_This_program_key_158
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "158"
    strings:
        $xord_158 = { ca f6 f7 ed be ee ec f1 f9 ec ff f3 }
    condition:
        any of them
}

rule xor_This_program_key_159
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "159"
    strings:
        $xord_159 = { cb f7 f6 ec bf ef ed f0 f8 ed fe f2 }
    condition:
        any of them
}

rule xor_This_program_key_160
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "160"
    strings:
        $xord_160 = { f4 c8 c9 d3 80 d0 d2 cf c7 d2 c1 cd }
    condition:
        any of them
}

rule xor_This_program_key_161
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "161"
    strings:
        $xord_161 = { f5 c9 c8 d2 81 d1 d3 ce c6 d3 c0 cc }
    condition:
        any of them
}

rule xor_This_program_key_162
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "162"
    strings:
        $xord_162 = { f6 ca cb d1 82 d2 d0 cd c5 d0 c3 cf }
    condition:
        any of them
}

rule xor_This_program_key_163
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "163"
    strings:
        $xord_163 = { f7 cb ca d0 83 d3 d1 cc c4 d1 c2 ce }
    condition:
        any of them
}

rule xor_This_program_key_164
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "164"
    strings:
        $xord_164 = { f0 cc cd d7 84 d4 d6 cb c3 d6 c5 c9 }
    condition:
        any of them
}

rule xor_This_program_key_165
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "165"
    strings:
        $xord_165 = { f1 cd cc d6 85 d5 d7 ca c2 d7 c4 c8 }
    condition:
        any of them
}

rule xor_This_program_key_166
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "166"
    strings:
        $xord_166 = { f2 ce cf d5 86 d6 d4 c9 c1 d4 c7 cb }
    condition:
        any of them
}

rule xor_This_program_key_167
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "167"
    strings:
        $xord_167 = { f3 cf ce d4 87 d7 d5 c8 c0 d5 c6 ca }
    condition:
        any of them
}

rule xor_This_program_key_168
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "168"
    strings:
        $xord_168 = { fc c0 c1 db 88 d8 da c7 cf da c9 c5 }
    condition:
        any of them
}

rule xor_This_program_key_169
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "169"
    strings:
        $xord_169 = { fd c1 c0 da 89 d9 db c6 ce db c8 c4 }
    condition:
        any of them
}

rule xor_This_program_key_170
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "170"
    strings:
        $xord_170 = { fe c2 c3 d9 8a da d8 c5 cd d8 cb c7 }
    condition:
        any of them
}

rule xor_This_program_key_171
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "171"
    strings:
        $xord_171 = { ff c3 c2 d8 8b db d9 c4 cc d9 ca c6 }
    condition:
        any of them
}

rule xor_This_program_key_172
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "172"
    strings:
        $xord_172 = { f8 c4 c5 df 8c dc de c3 cb de cd c1 }
    condition:
        any of them
}

rule xor_This_program_key_173
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "173"
    strings:
        $xord_173 = { f9 c5 c4 de 8d dd df c2 ca df cc c0 }
    condition:
        any of them
}

rule xor_This_program_key_174
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "174"
    strings:
        $xord_174 = { fa c6 c7 dd 8e de dc c1 c9 dc cf c3 }
    condition:
        any of them
}

rule xor_This_program_key_175
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "175"
    strings:
        $xord_175 = { fb c7 c6 dc 8f df dd c0 c8 dd ce c2 }
    condition:
        any of them
}

rule xor_This_program_key_176
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "176"
    strings:
        $xord_176 = { e4 d8 d9 c3 90 c0 c2 df d7 c2 d1 dd }
    condition:
        any of them
}

rule xor_This_program_key_177
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "177"
    strings:
        $xord_177 = { e5 d9 d8 c2 91 c1 c3 de d6 c3 d0 dc }
    condition:
        any of them
}

rule xor_This_program_key_178
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "178"
    strings:
        $xord_178 = { e6 da db c1 92 c2 c0 dd d5 c0 d3 df }
    condition:
        any of them
}

rule xor_This_program_key_179
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "179"
    strings:
        $xord_179 = { e7 db da c0 93 c3 c1 dc d4 c1 d2 de }
    condition:
        any of them
}

rule xor_This_program_key_180
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "180"
    strings:
        $xord_180 = { e0 dc dd c7 94 c4 c6 db d3 c6 d5 d9 }
    condition:
        any of them
}

rule xor_This_program_key_181
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "181"
    strings:
        $xord_181 = { e1 dd dc c6 95 c5 c7 da d2 c7 d4 d8 }
    condition:
        any of them
}

rule xor_This_program_key_182
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "182"
    strings:
        $xord_182 = { e2 de df c5 96 c6 c4 d9 d1 c4 d7 db }
    condition:
        any of them
}

rule xor_This_program_key_183
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "183"
    strings:
        $xord_183 = { e3 df de c4 97 c7 c5 d8 d0 c5 d6 da }
    condition:
        any of them
}

rule xor_This_program_key_184
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "184"
    strings:
        $xord_184 = { ec d0 d1 cb 98 c8 ca d7 df ca d9 d5 }
    condition:
        any of them
}

rule xor_This_program_key_185
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "185"
    strings:
        $xord_185 = { ed d1 d0 ca 99 c9 cb d6 de cb d8 d4 }
    condition:
        any of them
}

rule xor_This_program_key_186
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "186"
    strings:
        $xord_186 = { ee d2 d3 c9 9a ca c8 d5 dd c8 db d7 }
    condition:
        any of them
}

rule xor_This_program_key_187
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "187"
    strings:
        $xord_187 = { ef d3 d2 c8 9b cb c9 d4 dc c9 da d6 }
    condition:
        any of them
}

rule xor_This_program_key_188
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "188"
    strings:
        $xord_188 = { e8 d4 d5 cf 9c cc ce d3 db ce dd d1 }
    condition:
        any of them
}

rule xor_This_program_key_189
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "189"
    strings:
        $xord_189 = { e9 d5 d4 ce 9d cd cf d2 da cf dc d0 }
    condition:
        any of them
}

rule xor_This_program_key_190
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "190"
    strings:
        $xord_190 = { ea d6 d7 cd 9e ce cc d1 d9 cc df d3 }
    condition:
        any of them
}

rule xor_This_program_key_191
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "191"
    strings:
        $xord_191 = { eb d7 d6 cc 9f cf cd d0 d8 cd de d2 }
    condition:
        any of them
}

rule xor_This_program_key_192
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "192"
    strings:
        $xord_192 = { 94 a8 a9 b3 e0 b0 b2 af a7 b2 a1 ad }
    condition:
        any of them
}

rule xor_This_program_key_193
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "193"
    strings:
        $xord_193 = { 95 a9 a8 b2 e1 b1 b3 ae a6 b3 a0 ac }
    condition:
        any of them
}

rule xor_This_program_key_194
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "194"
    strings:
        $xord_194 = { 96 aa ab b1 e2 b2 b0 ad a5 b0 a3 af }
    condition:
        any of them
}

rule xor_This_program_key_195
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "195"
    strings:
        $xord_195 = { 97 ab aa b0 e3 b3 b1 ac a4 b1 a2 ae }
    condition:
        any of them
}

rule xor_This_program_key_196
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "196"
    strings:
        $xord_196 = { 90 ac ad b7 e4 b4 b6 ab a3 b6 a5 a9 }
    condition:
        any of them
}

rule xor_This_program_key_197
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "197"
    strings:
        $xord_197 = { 91 ad ac b6 e5 b5 b7 aa a2 b7 a4 a8 }
    condition:
        any of them
}

rule xor_This_program_key_198
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "198"
    strings:
        $xord_198 = { 92 ae af b5 e6 b6 b4 a9 a1 b4 a7 ab }
    condition:
        any of them
}

rule xor_This_program_key_199
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "199"
    strings:
        $xord_199 = { 93 af ae b4 e7 b7 b5 a8 a0 b5 a6 aa }
    condition:
        any of them
}

rule xor_This_program_key_200
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "200"
    strings:
        $xord_200 = { 9c a0 a1 bb e8 b8 ba a7 af ba a9 a5 }
    condition:
        any of them
}

rule xor_This_program_key_201
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "201"
    strings:
        $xord_201 = { 9d a1 a0 ba e9 b9 bb a6 ae bb a8 a4 }
    condition:
        any of them
}

rule xor_This_program_key_202
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "202"
    strings:
        $xord_202 = { 9e a2 a3 b9 ea ba b8 a5 ad b8 ab a7 }
    condition:
        any of them
}

rule xor_This_program_key_203
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "203"
    strings:
        $xord_203 = { 9f a3 a2 b8 eb bb b9 a4 ac b9 aa a6 }
    condition:
        any of them
}

rule xor_This_program_key_204
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "204"
    strings:
        $xord_204 = { 98 a4 a5 bf ec bc be a3 ab be ad a1 }
    condition:
        any of them
}

rule xor_This_program_key_205
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "205"
    strings:
        $xord_205 = { 99 a5 a4 be ed bd bf a2 aa bf ac a0 }
    condition:
        any of them
}

rule xor_This_program_key_206
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "206"
    strings:
        $xord_206 = { 9a a6 a7 bd ee be bc a1 a9 bc af a3 }
    condition:
        any of them
}

rule xor_This_program_key_207
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "207"
    strings:
        $xord_207 = { 9b a7 a6 bc ef bf bd a0 a8 bd ae a2 }
    condition:
        any of them
}

rule xor_This_program_key_208
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "208"
    strings:
        $xord_208 = { 84 b8 b9 a3 f0 a0 a2 bf b7 a2 b1 bd }
    condition:
        any of them
}

rule xor_This_program_key_209
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "209"
    strings:
        $xord_209 = { 85 b9 b8 a2 f1 a1 a3 be b6 a3 b0 bc }
    condition:
        any of them
}

rule xor_This_program_key_210
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "210"
    strings:
        $xord_210 = { 86 ba bb a1 f2 a2 a0 bd b5 a0 b3 bf }
    condition:
        any of them
}

rule xor_This_program_key_211
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "211"
    strings:
        $xord_211 = { 87 bb ba a0 f3 a3 a1 bc b4 a1 b2 be }
    condition:
        any of them
}

rule xor_This_program_key_212
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "212"
    strings:
        $xord_212 = { 80 bc bd a7 f4 a4 a6 bb b3 a6 b5 b9 }
    condition:
        any of them
}

rule xor_This_program_key_213
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "213"
    strings:
        $xord_213 = { 81 bd bc a6 f5 a5 a7 ba b2 a7 b4 b8 }
    condition:
        any of them
}

rule xor_This_program_key_214
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "214"
    strings:
        $xord_214 = { 82 be bf a5 f6 a6 a4 b9 b1 a4 b7 bb }
    condition:
        any of them
}

rule xor_This_program_key_215
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "215"
    strings:
        $xord_215 = { 83 bf be a4 f7 a7 a5 b8 b0 a5 b6 ba }
    condition:
        any of them
}

rule xor_This_program_key_216
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "216"
    strings:
        $xord_216 = { 8c b0 b1 ab f8 a8 aa b7 bf aa b9 b5 }
    condition:
        any of them
}

rule xor_This_program_key_217
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "217"
    strings:
        $xord_217 = { 8d b1 b0 aa f9 a9 ab b6 be ab b8 b4 }
    condition:
        any of them
}

rule xor_This_program_key_218
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "218"
    strings:
        $xord_218 = { 8e b2 b3 a9 fa aa a8 b5 bd a8 bb b7 }
    condition:
        any of them
}

rule xor_This_program_key_219
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "219"
    strings:
        $xord_219 = { 8f b3 b2 a8 fb ab a9 b4 bc a9 ba b6 }
    condition:
        any of them
}

rule xor_This_program_key_220
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "220"
    strings:
        $xord_220 = { 88 b4 b5 af fc ac ae b3 bb ae bd b1 }
    condition:
        any of them
}

rule xor_This_program_key_221
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "221"
    strings:
        $xord_221 = { 89 b5 b4 ae fd ad af b2 ba af bc b0 }
    condition:
        any of them
}

rule xor_This_program_key_222
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "222"
    strings:
        $xord_222 = { 8a b6 b7 ad fe ae ac b1 b9 ac bf b3 }
    condition:
        any of them
}

rule xor_This_program_key_223
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "223"
    strings:
        $xord_223 = { 8b b7 b6 ac ff af ad b0 b8 ad be b2 }
    condition:
        any of them
}

rule xor_This_program_key_224
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "224"
    strings:
        $xord_224 = { b4 88 89 93 c0 90 92 8f 87 92 81 8d }
    condition:
        any of them
}

rule xor_This_program_key_225
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "225"
    strings:
        $xord_225 = { b5 89 88 92 c1 91 93 8e 86 93 80 8c }
    condition:
        any of them
}

rule xor_This_program_key_226
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "226"
    strings:
        $xord_226 = { b6 8a 8b 91 c2 92 90 8d 85 90 83 8f }
    condition:
        any of them
}

rule xor_This_program_key_227
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "227"
    strings:
        $xord_227 = { b7 8b 8a 90 c3 93 91 8c 84 91 82 8e }
    condition:
        any of them
}

rule xor_This_program_key_228
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "228"
    strings:
        $xord_228 = { b0 8c 8d 97 c4 94 96 8b 83 96 85 89 }
    condition:
        any of them
}

rule xor_This_program_key_229
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "229"
    strings:
        $xord_229 = { b1 8d 8c 96 c5 95 97 8a 82 97 84 88 }
    condition:
        any of them
}

rule xor_This_program_key_230
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "230"
    strings:
        $xord_230 = { b2 8e 8f 95 c6 96 94 89 81 94 87 8b }
    condition:
        any of them
}

rule xor_This_program_key_231
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "231"
    strings:
        $xord_231 = { b3 8f 8e 94 c7 97 95 88 80 95 86 8a }
    condition:
        any of them
}

rule xor_This_program_key_232
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "232"
    strings:
        $xord_232 = { bc 80 81 9b c8 98 9a 87 8f 9a 89 85 }
    condition:
        any of them
}

rule xor_This_program_key_233
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "233"
    strings:
        $xord_233 = { bd 81 80 9a c9 99 9b 86 8e 9b 88 84 }
    condition:
        any of them
}

rule xor_This_program_key_234
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "234"
    strings:
        $xord_234 = { be 82 83 99 ca 9a 98 85 8d 98 8b 87 }
    condition:
        any of them
}

rule xor_This_program_key_235
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "235"
    strings:
        $xord_235 = { bf 83 82 98 cb 9b 99 84 8c 99 8a 86 }
    condition:
        any of them
}

rule xor_This_program_key_236
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "236"
    strings:
        $xord_236 = { b8 84 85 9f cc 9c 9e 83 8b 9e 8d 81 }
    condition:
        any of them
}

rule xor_This_program_key_237
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "237"
    strings:
        $xord_237 = { b9 85 84 9e cd 9d 9f 82 8a 9f 8c 80 }
    condition:
        any of them
}

rule xor_This_program_key_238
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "238"
    strings:
        $xord_238 = { ba 86 87 9d ce 9e 9c 81 89 9c 8f 83 }
    condition:
        any of them
}

rule xor_This_program_key_239
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "239"
    strings:
        $xord_239 = { bb 87 86 9c cf 9f 9d 80 88 9d 8e 82 }
    condition:
        any of them
}

rule xor_This_program_key_240
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "240"
    strings:
        $xord_240 = { a4 98 99 83 d0 80 82 9f 97 82 91 9d }
    condition:
        any of them
}

rule xor_This_program_key_241
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "241"
    strings:
        $xord_241 = { a5 99 98 82 d1 81 83 9e 96 83 90 9c }
    condition:
        any of them
}

rule xor_This_program_key_242
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "242"
    strings:
        $xord_242 = { a6 9a 9b 81 d2 82 80 9d 95 80 93 9f }
    condition:
        any of them
}

rule xor_This_program_key_243
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "243"
    strings:
        $xord_243 = { a7 9b 9a 80 d3 83 81 9c 94 81 92 9e }
    condition:
        any of them
}

rule xor_This_program_key_244
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "244"
    strings:
        $xord_244 = { a0 9c 9d 87 d4 84 86 9b 93 86 95 99 }
    condition:
        any of them
}

rule xor_This_program_key_245
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "245"
    strings:
        $xord_245 = { a1 9d 9c 86 d5 85 87 9a 92 87 94 98 }
    condition:
        any of them
}

rule xor_This_program_key_246
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "246"
    strings:
        $xord_246 = { a2 9e 9f 85 d6 86 84 99 91 84 97 9b }
    condition:
        any of them
}

rule xor_This_program_key_247
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "247"
    strings:
        $xord_247 = { a3 9f 9e 84 d7 87 85 98 90 85 96 9a }
    condition:
        any of them
}

rule xor_This_program_key_248
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "248"
    strings:
        $xord_248 = { ac 90 91 8b d8 88 8a 97 9f 8a 99 95 }
    condition:
        any of them
}

rule xor_This_program_key_249
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "249"
    strings:
        $xord_249 = { ad 91 90 8a d9 89 8b 96 9e 8b 98 94 }
    condition:
        any of them
}

rule xor_This_program_key_250
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "250"
    strings:
        $xord_250 = { ae 92 93 89 da 8a 88 95 9d 88 9b 97 }
    condition:
        any of them
}

rule xor_This_program_key_251
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "251"
    strings:
        $xord_251 = { af 93 92 88 db 8b 89 94 9c 89 9a 96 }
    condition:
        any of them
}

rule xor_This_program_key_252
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "252"
    strings:
        $xord_252 = { a8 94 95 8f dc 8c 8e 93 9b 8e 9d 91 }
    condition:
        any of them
}

rule xor_This_program_key_253
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "253"
    strings:
        $xord_253 = { a9 95 94 8e dd 8d 8f 92 9a 8f 9c 90 }
    condition:
        any of them
}

rule xor_This_program_key_254
{
    meta:
        plugin = "decoder:xor"
        save = "True"
        key = "254"
    strings:
        $xord_254 = { aa 96 97 8d de 8e 8c 91 99 8c 9f 93 }
    condition:
        any of them
}

