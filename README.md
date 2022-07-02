# FSProxyOpen
### Build 1.0.0.0

## 特徴
FSProxyOpenは、FSWorkbenchが利用する拡張サービスです。    
FSWorkbenchのプロセスコンテキストに代わってファイル，ディレクトリをオープンします。

[FSWorkbenchはこちらから（バイナリのみ公開中）](https://github.com/yamashita-software-works/FSWorkbench/releases)
<br>
>**Warning**<br>
実験用のサービスであり、調査、テスト、デバッグなどの環境下での使用を前提としています。<br>
日常的に使用しているPCでの実行はお勧めできません。<br>
<br>
使い終えたらサービスの停止・無効化またはアンインストールしておくことをお勧めします。<br>

<br>

## 機能
FSWorkbenchが通常では参照できないフォルダ（例えば"C:\System Volume Information"の様な）を参照できる様になります。
<br><br>
## 使用法
管理者権限で起動したコマンドプロンプト、PowerShellなどからSCコマンドを使用します。

適切で安全な場所に実行ファイルをコピーし、サービスとして登録します。
```
sc create fsproxyopen binPath= <コピーしたパス>\fsproxyopen.exe type= own start= demand error= normal
```

サービスを開始します。
```
sc start fsproxyopen
```

この時点でサービスが利用可能になります。
<br>
<br>

使い終わったら必ず停止させることをお勧めします。
```
sc stop fsproxyopen
```

不要になったら登録を解除します（ファイルも削除することをお勧めします）。
```
sc delete fsproxyopen
```
<br>

## FSWorkbenchの起動
fsworkbench.exe起動時に--enableproxyopenオプションを付けて実行します。
```
fsworkbench --enableproxyopen
```
FSWorkbenchは自身のセキュリティコンテキストでファイルをオープンできない場合に限り、サービスを利用してオープンを試みます。

<br>

## ビルド環境
Windows 7 WDK(Windows Driver Kit) 7.1.0の開発環境でビルドしています。

Windows 7 WDKは次の場所からダウンロードできます。  
[https://www.microsoft.com/en-us/download/details.aspx?id=11800](https://www.microsoft.com/en-us/download/details.aspx?id=11800)


>**Notice**   
Windows 10 のスタートメニューは、インストールされたWDKのビルド環境ショートカットリンクを正しく認識しません。<br>
そのため、以下の場所にあるショートカットリンクを直接実行するか使い易い場所にコピーしておいてください。<br><br>
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Windows Driver Kits\WDK 7600.16385.1\Build Environments\Windows 7<br><br>
例えばWDKでx64版実行ファイルを作成する場合は `x64 Free Build Environment.lnk` を開きます。

<br>

### ビルド方法
ソースコードを展開したディレクトリ（sourcesファイルが存在する）に移動してから、buildコマンドを実行します。 

```sh
build -c
```

x64版の場合ビルドが成功したら、ソースコードディレクトリ下の"objfre_win7_amd64\amd64"に実行ファイルが作成されます。

