# Drebin Feature Extractor

## 概要

Drebin Feature Extractorは、Androidアプリケーション（APKファイル）を静的解析し、Drebin論文で提案された特徴量を抽出してレポートを生成するツールです。

このツールは、論文 "Drebin: Effective and Explainable Detection of Android Malware in Your Pocket" で述べられている特徴量抽出フェーズの再現実装です。オリジナルの実装（Mobile-SandboxによるPython 2ベース）を参考に、**Python 3.8以上、OpenJDK 11、Android SDK 36** 環境で動作するように再構築しました。

抽出される特徴量はオリジナル論文に準拠していますが、**内部の実装は完全に異なっています**。このツールは、Androidマルウェア研究やアプリケーションの静的解析に利用できます。



## 本リポジトリのライセンス

以下にあるように、この実装はオリジナルの研究及び実装に触発されたものであり、ライセンスもこれを引き継がざるを得ません。よって、GNU GPL v3 を適用します。



**元の実装に関する情報 (Disclaimer)**

この実装は、以下のオリジナルの研究および実装に触発されたものです。オリジナルのコードには以下のライセンスが適用されていました。

```
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#########################################################################################
```





## ディレクトリ構造

```
. 
├── data/ # データ関連ファイル 
├── logs/ # ログファイル 
├── src/ # ソースコード 
│    ├── analyzer/ # APK解析モジュール 
│    ├── report/ # レポート生成モジュール 
│    ├── logger.py # ロギング設定 
│    ├── extractor.py # メイン抽出ロジック 
│    └── unpacker.py # APK解凍モジュール
└── tools/ # ツールスクリプト
```



## 必要条件

- Python 3.8 以上
  - `uv` 環境下で実行することを強く推奨します
- OpenJDK 11
- Android SDK 36



## インストール

1. [Android Studio 公式サイト](https://developer.android.com/studio) からAndroid Studioをダウンロード、インストール

2. `uv` をインストール

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. リポジトリのクローン

   ```
   git clone https://github.com/Almond-Latte/DrebinFeatureExtractor
   cd DrebinFeatureExtractor
   ```

4. 環境変数の設定

   - `.env.sample` をコピーして `.env` ファイルを作成します。

     ```bash
     cp .env.sample .env
     ```

   - `.env` ファイルを開き、Android SDKがインストールされた場所に編集します。

5. 依存関係のインストール

   ```bash
   uv sync
   ```



## 実行方法

### 一つのAPKを解析する場合

```bash
uv run src/extractor.py [sample_file] [report_dir] [working_dir]
```

- `[sample_file]` : 解析対象のAPKファイル
- `[report_dir]`: 特徴量レポートの出力先ディレクトリ
- `[working_dir]`: APKの展開などを行うための一時的な作業ディレクトリ(自動で削除されます)

- 実行方法は以下でも確認できます。

```bash
uv run src/extractor.py --help
```



### 指定したディレクトリ内のすべてのAPKファイルを解析する場合

```bash
uv run src/extension/feature_extraction_automation.py [apk_dir]
```

- `[apk_dir]`: 解析対象のAPKが格納されているディレクトリ



# 参考文献

- Arp, Daniel, et al. "Drebin: Effective and explainable detection of android malware in your pocket." *NDSS*. Vol. 14. 2014. 