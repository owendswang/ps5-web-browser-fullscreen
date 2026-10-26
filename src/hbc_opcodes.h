/* SPDX-License-Identifier: MIT
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Generated from Hermes v0.12.0 BytecodeList.def (HBC v89).
 * Upstream: https://github.com/facebook/hermes/tree/7d3e091b59ff5e5a9e722718c01d81dab52d4300
 * Regenerate from the pinned submodule with make opcodes.
 *
 * MIT License
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#define HBC_Unreachable 0
#define HBC_NewObjectWithBuffer 1
#define HBC_NewObjectWithBufferLong 2
#define HBC_NewObject 3
#define HBC_NewObjectWithParent 4
#define HBC_NewArrayWithBuffer 5
#define HBC_NewArrayWithBufferLong 6
#define HBC_NewArray 7
#define HBC_Mov 8
#define HBC_MovLong 9
#define HBC_Negate 10
#define HBC_Not 11
#define HBC_BitNot 12
#define HBC_TypeOf 13
#define HBC_Eq 14
#define HBC_StrictEq 15
#define HBC_Neq 16
#define HBC_StrictNeq 17
#define HBC_Less 18
#define HBC_LessEq 19
#define HBC_Greater 20
#define HBC_GreaterEq 21
#define HBC_Add 22
#define HBC_AddN 23
#define HBC_Mul 24
#define HBC_MulN 25
#define HBC_Div 26
#define HBC_DivN 27
#define HBC_Mod 28
#define HBC_Sub 29
#define HBC_SubN 30
#define HBC_LShift 31
#define HBC_RShift 32
#define HBC_URshift 33
#define HBC_BitAnd 34
#define HBC_BitXor 35
#define HBC_BitOr 36
#define HBC_Inc 37
#define HBC_Dec 38
#define HBC_InstanceOf 39
#define HBC_IsIn 40
#define HBC_GetEnvironment 41
#define HBC_StoreToEnvironment 42
#define HBC_StoreToEnvironmentL 43
#define HBC_StoreNPToEnvironment 44
#define HBC_StoreNPToEnvironmentL 45
#define HBC_LoadFromEnvironment 46
#define HBC_LoadFromEnvironmentL 47
#define HBC_GetGlobalObject 48
#define HBC_GetNewTarget 49
#define HBC_CreateEnvironment 50
#define HBC_DeclareGlobalVar 51
#define HBC_GetByIdShort 52
#define HBC_GetById 53
#define HBC_GetByIdLong 54
#define HBC_TryGetById 55
#define HBC_TryGetByIdLong 56
#define HBC_PutById 57
#define HBC_PutByIdLong 58
#define HBC_TryPutById 59
#define HBC_TryPutByIdLong 60
#define HBC_PutNewOwnByIdShort 61
#define HBC_PutNewOwnById 62
#define HBC_PutNewOwnByIdLong 63
#define HBC_PutNewOwnNEById 64
#define HBC_PutNewOwnNEByIdLong 65
#define HBC_PutOwnByIndex 66
#define HBC_PutOwnByIndexL 67
#define HBC_PutOwnByVal 68
#define HBC_DelById 69
#define HBC_DelByIdLong 70
#define HBC_GetByVal 71
#define HBC_PutByVal 72
#define HBC_DelByVal 73
#define HBC_PutOwnGetterSetterByVal 74
#define HBC_GetPNameList 75
#define HBC_GetNextPName 76
#define HBC_Call 77
#define HBC_Construct 78
#define HBC_Call1 79
#define HBC_CallDirect 80
#define HBC_Call2 81
#define HBC_Call3 82
#define HBC_Call4 83
#define HBC_CallLong 84
#define HBC_ConstructLong 85
#define HBC_CallDirectLongIndex 86
#define HBC_CallBuiltin 87
#define HBC_CallBuiltinLong 88
#define HBC_GetBuiltinClosure 89
#define HBC_Ret 90
#define HBC_Catch 91
#define HBC_DirectEval 92
#define HBC_Throw 93
#define HBC_ThrowIfEmpty 94
#define HBC_Debugger 95
#define HBC_AsyncBreakCheck 96
#define HBC_ProfilePoint 97
#define HBC_CreateClosure 98
#define HBC_CreateClosureLongIndex 99
#define HBC_CreateGeneratorClosure 100
#define HBC_CreateGeneratorClosureLongIndex 101
#define HBC_CreateAsyncClosure 102
#define HBC_CreateAsyncClosureLongIndex 103
#define HBC_CreateThis 104
#define HBC_SelectObject 105
#define HBC_LoadParam 106
#define HBC_LoadParamLong 107
#define HBC_LoadConstUInt8 108
#define HBC_LoadConstInt 109
#define HBC_LoadConstDouble 110
#define HBC_LoadConstBigInt 111
#define HBC_LoadConstBigIntLongIndex 112
#define HBC_LoadConstString 113
#define HBC_LoadConstStringLongIndex 114
#define HBC_LoadConstEmpty 115
#define HBC_LoadConstUndefined 116
#define HBC_LoadConstNull 117
#define HBC_LoadConstTrue 118
#define HBC_LoadConstFalse 119
#define HBC_LoadConstZero 120
#define HBC_CoerceThisNS 121
#define HBC_LoadThisNS 122
#define HBC_ToNumber 123
#define HBC_ToNumeric 124
#define HBC_ToInt32 125
#define HBC_AddEmptyString 126
#define HBC_GetArgumentsPropByVal 127
#define HBC_GetArgumentsLength 128
#define HBC_ReifyArguments 129
#define HBC_CreateRegExp 130
#define HBC_SwitchImm 131
#define HBC_StartGenerator 132
#define HBC_ResumeGenerator 133
#define HBC_CompleteGenerator 134
#define HBC_CreateGenerator 135
#define HBC_CreateGeneratorLongIndex 136
#define HBC_IteratorBegin 137
#define HBC_IteratorNext 138
#define HBC_IteratorClose 139
#define HBC_Jmp 140
#define HBC_JmpLong 141
#define HBC_JmpTrue 142
#define HBC_JmpTrueLong 143
#define HBC_JmpFalse 144
#define HBC_JmpFalseLong 145
#define HBC_JmpUndefined 146
#define HBC_JmpUndefinedLong 147
#define HBC_SaveGenerator 148
#define HBC_SaveGeneratorLong 149
#define HBC_JLess 150
#define HBC_JLessLong 151
#define HBC_JNotLess 152
#define HBC_JNotLessLong 153
#define HBC_JLessN 154
#define HBC_JLessNLong 155
#define HBC_JNotLessN 156
#define HBC_JNotLessNLong 157
#define HBC_JLessEqual 158
#define HBC_JLessEqualLong 159
#define HBC_JNotLessEqual 160
#define HBC_JNotLessEqualLong 161
#define HBC_JLessEqualN 162
#define HBC_JLessEqualNLong 163
#define HBC_JNotLessEqualN 164
#define HBC_JNotLessEqualNLong 165
#define HBC_JGreater 166
#define HBC_JGreaterLong 167
#define HBC_JNotGreater 168
#define HBC_JNotGreaterLong 169
#define HBC_JGreaterN 170
#define HBC_JGreaterNLong 171
#define HBC_JNotGreaterN 172
#define HBC_JNotGreaterNLong 173
#define HBC_JGreaterEqual 174
#define HBC_JGreaterEqualLong 175
#define HBC_JNotGreaterEqual 176
#define HBC_JNotGreaterEqualLong 177
#define HBC_JGreaterEqualN 178
#define HBC_JGreaterEqualNLong 179
#define HBC_JNotGreaterEqualN 180
#define HBC_JNotGreaterEqualNLong 181
#define HBC_JEqual 182
#define HBC_JEqualLong 183
#define HBC_JNotEqual 184
#define HBC_JNotEqualLong 185
#define HBC_JStrictEqual 186
#define HBC_JStrictEqualLong 187
#define HBC_JStrictNotEqual 188
#define HBC_JStrictNotEqualLong 189
#define HBC_Add32 190
#define HBC_Sub32 191
#define HBC_Mul32 192
#define HBC_Divi32 193
#define HBC_Divu32 194
#define HBC_Loadi8 195
#define HBC_Loadu8 196
#define HBC_Loadi16 197
#define HBC_Loadu16 198
#define HBC_Loadi32 199
#define HBC_Loadu32 200
#define HBC_Store8 201
#define HBC_Store16 202
#define HBC_Store32 203
static const unsigned char hbc_sizes[256] = {
    1,10,14,2,3,8,10,4,3,9,3,3,3,3,4,4,
    4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
    4,4,4,4,4,3,3,4,4,3,4,5,4,5,4,5,
    2,2,2,5,5,6,8,6,8,6,8,6,8,4,5,7,
    5,7,4,7,5,5,7,4,4,4,6,5,6,4,4,4,
    5,5,6,7,7,7,7,4,7,3,2,2,3,2,3,1,
    1,3,5,7,5,7,5,7,4,4,3,6,3,6,10,4,
    6,4,6,2,2,2,2,2,2,3,2,3,3,3,3,4,
    3,2,14,18,1,3,1,5,7,3,4,3,2,5,3,6,
    3,6,3,6,2,5,4,7,4,7,4,7,4,7,4,7,
    4,7,4,7,4,7,4,7,4,7,4,7,4,7,4,7,
    4,7,4,7,4,7,4,7,4,7,4,7,4,7,4,4,
    4,4,4,4,4,4,4,4,4,4,4,4,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
static const unsigned char hbc_string_offsets[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,1,4,4,4,4,4,4,4,4,4,3,3,3,
    3,3,0,0,0,3,3,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,2,2,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,6,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
static const unsigned char hbc_string_widths[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,4,1,2,4,2,4,2,4,2,4,1,2,4,
    2,4,0,0,0,2,4,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,2,4,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
static const unsigned char hbc_function_offsets[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,3,3,3,3,3,3,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,3,3,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
static const unsigned char hbc_function_widths[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,2,4,2,4,2,4,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,2,4,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
