# FSProxyOpen
### Build 1.0.0.0

## 特徴
FSProxyOpenは、FSWorkbenchが利用する拡張サービスです。    
FSWorkbenchのプロセスコンテキストに代わってファイル，ディレクトリをオープンします。

[FSWorkbenchはこちらから（バイナリのみ公開中）](https://github.com/yamashita-software-works/FSWorkbench/releases)
<br>
<br>
>**Warning**

実験用のサービスであり、調査、テスト、デバッグなどの環境下での使用を前提としています。
日常的に使用しているPCでの実行はお勧めできません。

使い終えたらサービスの停止・無効化またはアンインストールしておくことをお勧めします。

## 機能
FSWorkbenchが通常では参照できないフォルダ（例えば"C:\System Volume Information"の様な）を参照できる様になります。

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


## FSWorkbenchの起動

fsworkbench.exe起動時に--enableproxyopenオプションを付けて実行します。

```
fsworkbench --enableproxyopen
```

FSWorkbenchは自身のセキュリティコンテキストでファイルをオープンできない場合に限り、サービスを利用してオープンを試みます。

