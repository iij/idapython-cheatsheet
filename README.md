# IDAPythonチートシート

## はじめに

本ページは、IDA Proで利用することができるIDAPythonのチートシート集です。主に、マルウェア解析などリバースエンジニアリングを行う際に、便利なメソッドや使い方を紹介しています。より詳しく知りたい場合は、公式ドキュメント[IDAPython documentation](https://www.hex-rays.com/products/ida/support/idapython_docs/)をご参照ください。

## 目次

- [逆アセンブル](#逆アセンブル)
- [関数](#関数)
- [相互参照機能](#相互参照機能)
- [コメント](#コメント)
- [列挙型](#列挙型)
- [セグメント](#セグメント)
- [実行ファイルの情報](#実行ファイルの情報)

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

## セグメント

```python
for segment in idautils.Segments():
    segment_name = idc.get_segm_name(segment)
    segment_start_ea = idc.get_segm_start(segment)
    segment_end_ea = idc.get_segm_end(segment)
    print(f"{segment_name} {hex(segment_start_ea)} - {hex(segment_end_ea)}")
```

## 実行ファイルの情報

IDAでロードしている実行ファイルの情報を取得することができます。これにより、様々な条件分岐を実装しやすくなります。

```python
info = idaapi.get_inf_structure()
entrypoint = inf.start_ip
is_dll = info.is_dll()
is_x64 = info.is_64bit()
```