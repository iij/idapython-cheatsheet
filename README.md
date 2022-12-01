# IDAPythonチートシート (8.x)

## はじめに

本ページは、IDA Proで利用することができるIDAPythonのチートシート集です。主に、マルウェア解析などリバースエンジニアリングを行う際に、便利なメソッドや使い方を紹介しています。より詳しく知りたい場合は、公式ドキュメント[IDAPython documentation](https://www.hex-rays.com/products/ida/support/idapython_docs/)をご参照ください。

## 目次

- [モジュールの全体像](#モジュールの全体像)
- [アドレスの取得](#アドレスの取得)
- [逆アセンブル](#逆アセンブル)
- [関数](#関数)
- [相互参照機能](#相互参照機能)
- [コメント](#コメント)
- [色付け](#色付け)
- [名前変更](#名前変更)
- [列挙型](#列挙型)
- [構造体](#構造体)
- [セグメント](#セグメント)
- [デバッガ](#デバッガ)
- [実行ファイルの情報](#実行ファイルの情報)
- [困ったときは?](#困ったときは)

## モジュールの全体像

IDAPythonには、代表的な3つのモジュールが存在します。それぞれの役割は下記のとおりです。

|モジュール名|概要|
|:---|:---|
|idc|IDCの機能がラッピングされた互換用のモジュール|
|idaapi|low-levelなIDAに対するAPI用のモジュール|
|idautils|high-levelなIDAに対するAPI用のモジュール|

これらのIDAPythonモジュールの多くは、`ida_`というprefixから始まるファイル群をimportする形で実装されています。そのため、上記3つのモジュールでは、実装が難しいと感じた場合は、これらの個別モジュールを手掛かりに検索してみてください。

## アドレスの取得

GUI インターフェースからIDA Proを扱っている場合、いずれかのメソッドでカーソル上のアドレスを取得することができます。

```python
# どちらのメソッドでもカーソルが当たっているアドレスをint型で取得
ea = ida_kernwin.get_screen_ea()
ea = idc.here()
```

ea で指定されたアドレスの前後にあるアイテムの取得(命令かデータ)ができます。

```python
prev_ea = idc.prev_head(ea)
next_ea = idc.next_head(ea)
```

## 逆アセンブル

簡易的な逆アセンブル結果の取得には、下記のメソッドたちが便利です。

```python
idc.generate_disasm_line(ea, 0) # 対象アドレスの逆アセンブル結果を取得
idc.print_insn_mnem(ea) # 対象アドレスのニーモニックのみを取得
idc.get_operand_value(ea, 0) # 対象アドレスの1番目のオペランドを取得
idc.get_operand_value(ea, 1) # 対象アドレスの2番目のオペランドを取得
```

オペランドの種類（即値、レジスタ、メモリなど）について条件分岐などをしたい場合は、`get_operand_type`メソッドが便利です。比較対象となるオペランド種類の一覧は、[ida_uaモジュール](https://hex-rays.com/products/ida/support/idapython_docs/ida_ua.html)にまとまっています。

```python
op1_type = idc.get_operand_type(ea, 0) # 対象アドレスの1番目のオペランドの種類を取得
if op1_type == o_reg: # 対象オペランドがレジスタの場合
    print("First operand is Register")
```

## 関数

### 関数のアドレス情報の取得

```python
func = ida_funcs.get_func(ea) # func_t型
print(hex(func.start_ea)) # 関数の先頭アドレスの取得
print(hex(func.end_ea)) # 関数の末尾アドレスの取得
```

### 関数の属性情報の取得

関数の属性一覧は、[ida_funcsモジュール](https://www.hex-rays.com/products/ida/support/idadoc/337.shtml)にまとまっています。

```python
func_flags = idc.get_func_attr(ea, FUNCATTR_FLAGS)
if func_flags & FUNC_LIB:
    print(f"{hex(ea)}: FUNC_LIB")
```

### 全ての関数のアドレスと名前の取得

```python
for func in idautils.Functions():
    func_name = idc.get_func_name(func)
    print(f"{hex(func)}: {func_name}")
```

## 相互参照機能

### 参照元のアドレス一覧を表示

```python
for ref in idautils.XrefsTo(ea):
    print(hex(ref.frm))
```

## コメント

```python
is_repeatable = True
idc.set_cmt(ea, comment, is_repeatable)
idc.get_cmt(ea, is_repeatable)
idc.set_func_cmt(ea, comment, is_repeatable)
idc.get_func_cmt(ea, is_repeatable)
```

## 色付け

IDAでは、逆アセンブル画面などに対して、背景色の設定などが可能です。色付けする対象として、行、セグメント、関数レベルで行うことができます。`idc.set_color`メソッドの第2引数で色付けをする対象を指定します。第3引数で、色を指定します。背景色の取得には、`idc.get_color`メソッドが利用できます。

```python
idc.set_color(ea, idc.CIC_ITEM, 0xffff00)
color = idc.get_color(ea, idc.CIC_ITEM)
```

## 名前変更

解析している際に、変数名や関数名を変更したいと感じることがあります。その際には、`idc.set_name`メソッドが便利です。

```python
idc.set_name(ea, "new_func_name")
```

## データ操作

アドレスに格納されたデータをbytes型として読み書きすることができます。
```python
data = idaapi.get_bytes(ea, byte_size) # bytes型
idaapi.patch_bytes(ea, data)
```

int型としての値が欲しい場合や、書き込みたい際には、バイトサイズ毎に異なるメソッドを使うこともできます。

```python
idaapi.get_qword(ea) # 8byte
idaapi.patch_qword(ea, data) # 8byte
idaapi.get_dword(ea) # 4byte
idaapi.patch_dword(ea, data) # 4byte
idaapi.get_word(ea) # 2byte
idaapi.patch_word(ea, data) # 2byte
idaapi.get_word(ea) # 2byte
idaapi.get_byte(ea) # 1byte
idaapi.patch_byte(ea, data) # 1byte
```

### 列挙型

#### 列挙型の作成

```python
enum_name = "my_enum"
idc.add_enum(idaapi.BADNODE, enum_name, idaapi.hex_flag())
idc.add_enum_member(enum_id, "sample", 0xcafebabe, idaapi.BADNODE)
```

#### 数値と定数のマッピング

`op_enum`メソッドを使うことで、ロードしている列挙型を用いて、数値を変換することができます。第2引数に変換する対象のオペランドの位置を指定します。ここでは、1個目のオペランドを意味する0を指定しています。

```python
enum_name = "my_enum"
enum_id = idaapi.get_enum(enum_name)
op_enum(ea, 0, enum_id, 0)
```

#### 定数名の取得

ある数値から、列挙型の定数名を取得することができます。

```python
enum_name = "my_enum"
value = 0xcafebabe
enum_id = get_enum(enum_name)
enum_member_id = idaapi.get_enum_member(enum_id, value, 0, 0)
enum_member_name = idaapi.get_enum_member_name(enum_member_id)
```

### 構造体

`ida_struct` モジュールを利用することで構造体の操作ができます。

#### 構造体の作成とメンバーの追加

```c
struct my_structure {
    int sample_member1;
    short sample_member2;
    char sample_member3;
    char sample_member[15];
};
```

上記のような`my_structure`構造体を作成する場合、下記のようにして作成することができます。

```python
ida_struct.add_struc(0, "my_structure")
id = ida_struct.get_struc_id("my_structure")
st = ida_struct.get_struc(id)

# オフセット0にDWORD型で "sample_member1" というメンバーを追加
ida_struct.add_struc_member(st, "sample_member1", 0, idaapi.FF_DWORD, None, 4)
# オフセット4にWORD型で "sample_member2" というメンバーを追加
ida_struct.add_struc_member(st, "sample_member2", 4, idaapi.FF_WORD, None, 2)
# オフセット6にBYTE型で "sample_member3" というメンバーを追加
ida_struct.add_struc_member(st, "sample_member3", 6, idaapi.FF_BYTE, None, 1)
# 構造体の一番最後にBYTE型で15バイト分の配列を確保した "sample_member4" というメンバーを追加
ida_struct.add_struc_member(st, "sample_member4", idaapi.BADADDR, idaapi.FF_BYTE, None, 15)
```

#### 構造体のメンバーの削除
```python
# オフセット6のメンバーを削除("my_structure" の例では "sample_member2" を削除)
ida_struct.del_struc_member(st, 6)
```

#### 構造体からの情報取得

宣言されているすべての構造体を列挙することもできます。  
特定の名称の構造体を見つけて処理をしたい場合などに使用できます。

```python
size: int = ida_struct.get_struc_qty()
idx: int = ida_struct.get_first_struc_idx()
for _ in range(size):
    id: int = ida_struct.get_struc_by_idx(idx)
    name: str = ida_struct.get_struc_name(id)
    print(f"[{idx}]: struct_{hex(id)}: {name}")
    idx = ida_struct.get_next_struc_idx(idx)
```

#### 特定の構造体からのメンバ情報取得

1つの構造体を指定して、メンバーの詳細を確認することができます。
ここでは、メンバ情報の一覧を列挙しています。

```python
id = ida_struct.get_struc_id("my_structure")
st = ida_struct.get_struc(id)
size = ida_struct.get_struc_size(st)

idx: int = 0
while(idx <= size):
    member_id: int = ida_struct.get_member_id(st, idx)
    # undefined なメンバーは飛ばす
    if member_id == 0xffffffff:
        idx += 1
        continue
    member_name: str = ida_struct.get_struc_name(member_id)
    member_t = ida_struct.get_member_by_fullname(member_name)
    member_size: int = ida_struct.get_member_size(member_t[0])
    print(f"[{hex(idx)}]: {member_name}, size: {member_size}")
    idx = idx + member_size
```

### Type Libraryで定義した構造体のロード

`idc.add_default_til`メソッドで、Type Libraryのロードをすることができます。戻り値として、ロード済みかの真偽値を返します。`idc.import_type`メソッドを用いることで、Type Libraryにある構造体をロードすることができます。

```python
is_loaded = idc.add_default_til("ntapi64_win7")
if is_loaded:
    idc.import_type(-1, "IMAGE_DOS_HEADER")
    idc.import_type(-1, "IMAGE_NT_HEADERS64")
```

## セグメント

```python
for segment in idautils.Segments():
    segment_name = idc.get_segm_name(segment)
    segment_start_ea = idc.get_segm_start(segment)
    segment_end_ea = idc.get_segm_end(segment)
    print(f"{segment_name} {hex(segment_start_ea)} - {hex(segment_end_ea)}")
```

## デバッガ
`ida_dbg` モジュールを使用することで、APIからデバッガフックをかけることができます。

### ブレークポイントの設定
```python
ida_dbg.add_bpt(ea) #ブレークポイント追加
ida_dbg.enable_bpt(ea) #ブレークポイント有効
ida_dbg.disable_bpt(ea) #ブレークポイント無効
ida_dbg.del_bpt(ea) #ブレークポイント削除
```

### デバッグ操作

いずれもブレークポイントの設定なしで、処理終了後に止まります。デバッグ中のみ使用できます。

```python
ida_dbg.run_to(ea) # eaで指定したアドレスまで実行()
ida_dbg.step_into()
ida_dbg.step_over()
ida_dbg.step_until_ret()
```

ブレークポイントまで実行し続けます。

```python
ida_dbg.continue_process()
```

### レジスタの操作

デバッグ中に限り、レジスタ値の読み書きができます。

```python
ida_dbg.get_reg_val("eip") # eipレジスタの値をint型で取得
ida_dbg.set_reg_val("eax", 0xffffff) # eaxレジスタの値を 0xffffff へ変更
```


## 実行ファイルの情報

IDAでロードしている実行ファイルの情報を取得することができます。これにより、様々な条件分岐を実装しやすくなります。

```python
info = idaapi.get_inf_structure()
entrypoint = inf.start_ip
is_dll = info.is_dll()
is_x64 = info.is_64bit()
```

## 困ったときは?

冒頭で公式ドキュメントを紹介しましたが、メソッドの入出力やモジュールで使用可能なメソッドを調べる場合、検索が少々手間となる場合があります。  
モジュールやメソッドの名称がすでにわかっているときは、IDA Proの下部に表示されている `Output` のコンソール上で `?` を使って検索しましょう。  
例えば、`ida_funcs.get_func` メソッドの詳細な入出力を調査したい場合、以下のようにコンソール上で入力することで Help を簡単に表示させることができます。

```sh
Python>?ida_funcs.get_func
Help on function get_func in module ida_funcs:

get_func(*args) -> 'func_t *'
    get_func(ea) -> func_t
    Get pointer to function structure by address.
    
    @param ea: (C++: ea_t) any address in a function
    @return: ptr to a function or nullptr. This function returns a function entry
             chunk.
```

モジュールも同様に Help を表示できます。使用方法がわからないときがあった場合は積極的に叩いてみるとよいでしょう。

```sh
Python>?ida_funcs
Help on module ida_funcs:

NAME
    ida_funcs - Routines for working with functions within the disassembled program.

DESCRIPTION
    This file also contains routines for working with library signatures (e.g.
    FLIRT).
    
    Each function consists of function chunks. At least one function chunk must be
    present in the function definition - the function entry chunk. Other chunks are
    called function tails. There may be several of them for a function.

(snip.)

FUNCTIONS
    add_func(*args) -> 'bool'
        add_func(ea1, ea2=BADADDR) -> bool
        Add a new function. If the function end address is BADADDR, then IDA will try to
        determine the function bounds by calling find_func_bounds(...,
        FIND_FUNC_DEFINE).
        
        @param ea1: (C++: ea_t) start address
        @param ea2: (C++: ea_t) end address
        @return: success
    
    add_func_ex(*args) -> 'bool'
        ...

(snip.)
```
