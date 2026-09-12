# LicenseSmith — Threat Model / 脅威モデル

Document version 1.0 — 2026-09-07
Applies to key format `LS1` (see `spec/key-format.md`).

**This document is written twice: English first, Japanese (日本語) below. The two halves say the same thing.**
**本文書は英語と日本語の2言語で同じ内容を記載しています。英語が上、日本語が下です。**

---
---

# English

## 1. Read this first

LicenseSmith gives you two guarantees, and no others.

It guarantees the **authenticity** of a license key — that the key was issued by whoever holds your private
key — and its **integrity** — that the payload inside it (product ID, seat count, expiry, feature flags,
buyer identifier) is exactly what was signed and has not been altered since. **It does not, and cannot,
prevent an attacker from modifying your compiled application so that the verification call is removed,
skipped, or forced to report success.** Anyone who can edit the bytes of a program running on their own
machine can edit the branch that checks the license. That is a property of shipping software to hardware
you do not control. It is not a shortcoming of Ed25519, it is not a shortcoming of this kit, and it is not
solved by moving the check to a server. Every other statement in this document follows from that paragraph.

If you need one sentence for your own users: *this tool tells you whether a license key is real and
unmodified; it does not stop someone from tearing the lock off the door.*

**At a glance:**

| Prevented | Not prevented |
|---|---|
| P1 Key forgery | N1 Binary patching removes the check |
| P2 Payload tampering (expiry, feature flags, etc.) | N2 Key sharing by a paying customer |
| P3 Cross-product key reuse | N3 Private key leaks |
| P4 Use of an expired key | N4 Public key substitution |
| | N5 System clock set backwards |

If you are in a hurry, once this table has given you the gist, feel free to skip ahead to "7. Suggested
wording for your own users and store listing".

## 2. Cryptographic basis

LicenseSmith signs with **Ed25519** (RFC 8032). The kit relies only on the following widely documented
properties of that scheme:

| Property | Value |
|---|---|
| Security level | approximately 128 bits |
| Signature size | 64 bytes |
| Public key size | 32 bytes |
| Signature determinism | deterministic — the same message and key always produce the same signature, with no per-signature randomness required |

This document deliberately makes **no numerical claim** about how long any particular attack would take,
quotes no benchmark figures, and does not compare Ed25519 to other schemes. If you want such numbers, take
them from RFC 8032 and from the published cryptographic literature, not from a vendor document.

What is signed is the **ASCII byte string `LS1.<payload_b64url>`**, not a re-serialised JSON object. The
verifier checks the signature over those bytes *before* parsing any JSON, so a payload that fails
verification never reaches your parsing code. See `spec/key-format.md` for the exact layout and the fixed
order in which error codes are decided.

## 3. Actors, assets and assumptions

| | |
|---|---|
| **You (the vendor)** | Hold the Ed25519 private key on a machine you control. Issue keys with the CLI. |
| **Your buyer** | Receives a license key string. Runs your application on their own machine. |
| **The attacker** | Has full physical and administrative control of the machine your application runs on. Can read, modify, replace and delete every byte your installer wrote, including the embedded public key. Can attach a debugger. Has unlimited time and no network restrictions. |
| **The asset being protected** | Your revenue — specifically, the difference between users who pay and users who would have paid but did not. |
| **The asset that must stay secret** | The Ed25519 private key. Nothing else in this system is secret; the format, the verifier source, the public key and the test vectors are all publishable. |
| **Assumption 1** | Verification runs entirely locally. No network is contacted at verification time. |
| **Assumption 2** | The current time comes from the operating system clock that the end user controls. |
| **Assumption 3** | The Ed25519 implementations used are correct (paid kit: see `docs/THIRD-PARTY.md`; this free verifier's only dependency is `@noble/ed25519`). The kit does not audit them. |

## 4. What this prevents, and what it does not

### 4.1 Prevented

| # | Threat | Why it is prevented |
|---|---|---|
| **P1** | **Key forgery** — producing a license string that a verifier accepts, without your private key | Acceptance requires a valid Ed25519 signature over the exact bytes `LS1.<payload_b64url>`. Producing such a signature without the private key is the problem Ed25519 is designed to make computationally infeasible. |
| **P2** | **Payload tampering** — editing `seats`, `exp`, `feat`, `sub`, `pid`, `lid` or any other field of a real, issued key | The signature covers the encoded payload bytes. Changing any field changes those bytes, so verification returns `bad_signature`. Because the signature is checked before JSON parsing, a doctored payload is rejected without ever being interpreted. |
| **P3** | **Cross-product key reuse** — using a key you issued for product A to unlock product B | The signed payload carries `pid`. When the verifier is called with a `productId`, a mismatch returns `product_mismatch`. `pid` is inside the signed bytes, so it cannot be rewritten to match. |
| **P4** | **Use of an expired key** — extending a time-limited license by editing it | `exp` is inside the signed bytes and cannot be extended. The verifier returns `expired` once the clock it reads is past `exp`. (Read together with N5: the clock belongs to the user.) |

**P1 through P4 hold only while your program actually calls the verifier and acts on its answer.** They are
statements about the key format, not about your application. See N1.

### 4.2 Not prevented

| # | Threat | Short reason |
|---|---|---|
| **N1** | **Binary patching** — removing the verification call, jumping past it, or forcing it to report success | The code runs on the attacker's machine, and they can edit it. |
| **N2** | **Key sharing by a paying customer** — a legitimate buyer posts or passes on their key | The shared key is a genuine, correctly signed key wherever it is used. Offline verification has nothing to compare it against. |
| **N3** | **Forgery after your private key leaks** | Anyone holding the private key is, to every verifier in the world, indistinguishable from you. |
| **N4** | **Public key substitution** — the attacker replaces the embedded public key with their own and re-signs a payload of their choosing | The trust anchor is a 32-byte value sitting in a file the attacker can edit. |
| **N5** | **Clock manipulation** — setting the system clock backwards to defeat `exp` | There is no trusted time source in an offline scheme. |

## 5. Not prevented — detail, mitigation, and the limit of each mitigation

None of the following is a solution. Each is a **mitigation**: it changes the cost or the payoff of an
attack by some amount you cannot measure, and it leaves the underlying threat in place. They are listed so
that you can decide which trade-offs are worth their cost to your legitimate users, and so that you can
describe them accurately in your own product's documentation.

### N1 — Binary patching removes the check

*Mitigation.* Call the verifier from more than one place, and let real program behaviour depend on payload
values rather than on a single boolean — derive the feature set from `feat`, derive a limit from `seats`,
so that deleting one branch produces a build that is visibly wrong rather than a build that is unlocked.
Ship updates often, so that a patched build goes stale and the pirated path costs ongoing effort.
*Limit.* Both measures raise the cost of an attack by an amount you cannot measure and do not remove it; an
attacker willing to patch build *n* will patch build *n+1*. LicenseSmith deliberately ships no
obfuscation and no anti-debugging (a non-goal of this kit), because those features mainly sell the feeling
of protection rather than protection. This holds whether the check is local or made against a server:
moving verification online does not change it, because the call is still just another branch inside a
binary the attacker already controls (§6).

### N2 — A paying customer shares their key

*Mitigation.* (a) Ship a **revocation list** inside your application and revoke the `lid` of any key
you find posted publicly, distributing the updated list with your normal releases. (b) **Bind a key to a
machine fingerprint** so one key stops working on many machines. (c) Put the buyer's identity in `sub` and
keep `seats` meaningful, so a leaked key points back at whoever leaked it.
*Limit.* A revocation list only reaches users who install the update carrying it, so revocation is always
late and never reaches anyone who has stopped updating. **The list the kit exports is not signed**, so it
is only as trustworthy as the application bundle you embed it in: do not fetch it at runtime over a
channel you do not control, because an attacker in the middle can serve an empty one (see
`docs/revocation.md` §5, included with the paid kit). Machine binding penalises legitimate users who
reinstall, replace hardware, or work across two machines. In practice this generates support load from
paying customers while a sharer can simply pass on a patched build instead. Traceability deters some
sharing; it blocks none.
*Not in the kit.* Of the three, only (a) and (c) are implemented: the CLI keeps a ledger and exports a
revocation list, and `sub`/`seats` travel inside the signed payload. Machine binding (b) is not provided,
`seats` is informational and never enforced by the verifiers (`spec/key-format.md` §3), and floating or
concurrent-use licensing is a non-goal — the number of copies in use at once cannot be counted without a
server. The paid kit's `README.md` §7 ("What LicenseSmith does not do") lists these in one place.

### N3 — Your private key leaks

*Mitigation.* Generate a new keypair, ship the new public key in an application update, and re-issue keys to
your existing buyers (the CLI's batch command exists partly for this). Store the private key offline, back
it up, and never commit it to a repository.
*Limit.* Every copy of your application already installed keeps trusting the old public key, and you cannot
recall those copies. Keys forged against the leaked private key stay acceptable to those builds for as long
as they remain in use. There is no revocation path for a compromised signing key in an offline scheme —
this is the one failure whose cost you cannot cap after the fact, which is why key storage deserves more of
your attention than any measure listed above.

### N4 — The embedded public key is replaced and the payload re-signed

*Mitigation.* Sign and distribute your releases through a channel that carries publisher identity — OS code
signing, a platform store, or checksums published from your own domain — so that a re-signed build is at
least distinguishable from yours by a user who cares to look.
*Limit.* This protects your distribution channel and your reputation with users who did not intend to run a
modified build. It offers nothing at all against a user who deliberately installs the modified build. Note
also that N4 requires the same capability as N1, so an attacker who has one has both; N4 mainly matters when
someone wants to redistribute a "working" build to others rather than merely unlock their own copy.

### N5 — The system clock is set backwards

*Mitigation.* (a) Record the highest timestamp your application has ever observed in local state, and treat
a clock reading earlier than that as suspect (a monotonic high-water mark). (b) Prefer `upd` — the update
entitlement cutoff — over `exp` for one-time-purchase products, so that what decays over time is *access to
new versions*, which you deliver and therefore control, rather than *the ability to run*, which depends on
their clock.
*Limit.* The high-water mark is local state, and is exactly as editable as the binary that wrote it; a fresh
profile or a clean install resets it. It also misfires on legitimate users whose clock was wrong, who move
between time settings, or who restore from a backup. `upd` reshapes the incentive rather than enforcing
anything: a user who never updates is unaffected by it.

## 6. Why an offline scheme is still worth selling

These are observations, not reassurance. Weigh them yourself.

1. **Most people who use your software will pay, if paying is easy and the price is fair.** A license key's
   job is to make the paid path the default and the unpaid path a deliberate act — not to eliminate the
   unpaid path. Measures aimed at the last few percent of users tend to cost more, in support burden and in
   friction for paying customers, than the revenue they recover.

2. **An attacker willing to patch your binary defeats online verification too.** A network check is one more
   branch in the same binary. Removing it is no harder than removing a local signature check, and in
   practice it is often easier: the response can be faked, the hostname can be redirected in `hosts`, or the
   check can be made to fail open. Online verification raises the bar against casual key sharing; it does
   not raise the bar against binary modification, because it lives in the same place the attacker already
   controls.

3. **The one thing a server can do that offline cannot is *detect* key sharing** — the same key checking in
   from many installations. Note the word: detection, after the fact, not prevention. And it is imperfect.
   NAT and VPNs collapse many users into one address; one legitimate customer routinely has a laptop, a
   desktop and a virtual machine; users who are offline generate no signal at all; and every threshold you
   pick eventually accuses a paying customer of piracy. Sharing detection is a real capability with real
   costs, not a clean win.

4. **Server verification is not free.** It adds a runtime dependency that can be slow or down, a bill that
   recurs every month for the lifetime of a product you sold once, a privacy surface (you are now logging
   who runs your software and when), and a component that breaks when you migrate payment platforms.

Offline verification trades away sharing detection. In exchange it never has an outage, never adds latency
to your application's startup, costs nothing to run, keeps working when your payment provider is acquired
or shut down, and works for users with no network at all.

## 7. Suggested wording for your own users and store listing

Do not claim more than the mechanism does. Accurate wording is also the wording that survives contact with
a sceptical audience:

> Licenses are verified locally with an Ed25519 signature. This confirms that your key was issued by us and
> has not been modified. It does not phone home, and it does not collect any information about you.

Avoid describing this or any other license scheme in absolute terms. The kit's `README.md` and the store
listing are both covered by the same self-check recorded in the appendix below.

---
---

# 日本語

## 1. 最初に読んでください

LicenseSmith が保証するのは 2 点だけです。

ライセンスキーの**真正性**——そのキーを発行したのは確かにあなたの秘密鍵を持つ者である——と、**完全性**——
キーの中の payload（製品ID、シート数、有効期限、機能フラグ、購入者識別子）が署名された内容そのままであり、
以後書き換えられていない——の 2 点です。**一方で本製品は、攻撃者があなたのコンパイル済みアプリケーションを
改変し、検証呼び出しを除去する・迂回する・成功したことにする、という攻撃を防ぎません。防げません。**
自分のマシン上で動くプログラムのバイト列を書き換えられる者は、ライセンスを確認している分岐も書き換えられ
ます。これは「自分の管理下にないハードウェアにソフトウェアを出荷する」ことの性質です。Ed25519 の欠点
でも本キットの欠点でもなく、検証をサーバーに移しても解消しません。本文書の他のすべての記述は、この段落から
導かれます。

自分のユーザーに一文で伝えるなら——*この仕組みは「そのライセンスキーが本物で、改変されていないか」を判定
する。ドアごと壊して入る行為を止めるものではない。*

**早見表:**

| 防げること | 防げないこと |
|---|---|
| P1 鍵の偽造 | N1 バイナリを改造して検証を消される |
| P2 中身の改竄（期限・機能フラグ等） | N2 正規購入者によるキーの共有 |
| P3 他製品への流用 | N3 秘密鍵の漏洩 |
| P4 期限切れキーの延命 | N4 公開鍵のすり替え |
| | N5 PCの時計を巻き戻される |

急いでいる方は、この表で概要をつかんだら「7. 自分のユーザー向け・出品ページ向けの推奨表現」まで読み飛ばして
構いません。

## 2. 暗号の基礎

LicenseSmith は **Ed25519**（RFC 8032）で署名します。本キットが依拠するのは、この方式について広く文書化
されている次の性質のみです。

| 性質 | 値 |
|---|---|
| セキュリティレベル | 約 128 ビット相当 |
| 署名長 | 64 バイト |
| 公開鍵長 | 32 バイト |
| 署名の決定論性 | 決定論的——同じメッセージと同じ鍵からは常に同じ署名が得られ、署名ごとの乱数を必要としない |

本文書は、特定の攻撃に要する時間についての**数値的な主張を一切行いません**。ベンチマーク値も引用せず、他
方式との比較も行いません。そうした数値が必要な場合は、販売者の文書ではなく RFC 8032 と公開された暗号学の
文献から取ってください。

署名対象は、JSON を再シリアライズしたものではなく、**ASCII バイト列 `LS1.<payload_b64url>` そのもの**です。
検証側は JSON をパースする**前に**そのバイト列に対して署名を検証するため、検証に失敗した payload があなたの
パース処理に届くことはありません。正確なレイアウトとエラーコードの判定順序は `spec/key-format.md` を参照
してください。

## 3. 登場人物・資産・前提

| | |
|---|---|
| **あなた（販売者）** | 自分の管理下のマシンで Ed25519 秘密鍵を保持し、CLI でキーを発行する。 |
| **購入者** | ライセンスキー文字列を受け取り、自分のマシンであなたのアプリケーションを動かす。 |
| **攻撃者** | アプリケーションが動作するマシンを物理的にも管理者権限的にも完全に掌握している。インストーラが書き込んだすべてのバイト（埋め込まれた公開鍵を含む）を読み・書き換え・置換・削除できる。デバッガを接続できる。時間は無制限で、ネットワーク上の制約もない。 |
| **守る対象** | 売上——正確には「支払ったユーザー」と「支払ったはずだが支払わなかったユーザー」の差分。 |
| **秘密にすべき資産** | Ed25519 秘密鍵。それ以外にこのシステムに秘密はない。フォーマット、検証実装のソース、公開鍵、テストベクタはすべて公開してよい。 |
| **前提 1** | 検証は完全にローカルで行われる。検証時にネットワークへは接続しない。 |
| **前提 2** | 現在時刻は、エンドユーザーが制御する OS のクロックから得る。 |
| **前提 3** | 使用する Ed25519 実装は正しい（有料キットでは `docs/THIRD-PARTY.md` を参照。この参照実装（MIT）の依存は
`@noble/ed25519` のみ）。本キットはそれらを監査していない。 |

## 4. 防げること／防げないこと

### 4.1 防げること

| # | 脅威 | 防げる理由 |
|---|---|---|
| **P1** | **キーの偽造**——秘密鍵なしに、検証実装が受理するライセンス文字列を作る | 受理には、バイト列 `LS1.<payload_b64url>` に対する正当な Ed25519 署名が必要。秘密鍵なしにその署名を作ることは、Ed25519 が計算量的に困難にするよう設計している当の問題である。 |
| **P2** | **payload の改竄**——実際に発行されたキーの `seats`・`exp`・`feat`・`sub`・`pid`・`lid` などを書き換える | 署名はエンコード済み payload のバイト列を対象とする。どのフィールドを変えてもそのバイト列が変わるため、検証は `bad_signature` を返す。署名検証は JSON パースより先に行われるので、改竄された payload は解釈されることなく拒否される。 |
| **P3** | **他製品のキーの流用**——製品 A 向けに発行したキーで製品 B を解錠する | 署名対象の payload に `pid` が含まれる。検証時に `productId` を渡せば、不一致は `product_mismatch` となる。`pid` は署名されたバイト列の内側にあるため、一致するよう書き換えることはできない。 |
| **P4** | **期限切れキーの利用**——期限つきライセンスを書き換えて延長する | `exp` は署名されたバイト列の内側にあり、延長できない。読み取った時刻が `exp` を過ぎていれば、検証は `expired` を返す。（後述 N5 と併せて読むこと。クロックはユーザーのものである。） |

**P1〜P4 が成り立つのは、あなたのプログラムが実際に検証実装を呼び出し、その結果に従って動作している間だけ
です。** これらはキーフォーマットについての主張であって、あなたのアプリケーションについての主張ではありま
せん。N1 を参照してください。

### 4.2 防げないこと

| # | 脅威 | 理由（要約） |
|---|---|---|
| **N1** | **バイナリの改変**——検証呼び出しを除去する、飛び越す、成功を返させる | コードは攻撃者のマシンで動いており、攻撃者はそれを書き換えられる。 |
| **N2** | **正規購入者によるキーの共有**——購入者が自分のキーを公開・譲渡する | 共有されたキーは、どこで使われても本物の正しく署名されたキーである。オフライン検証には照合する相手がいない。 |
| **N3** | **秘密鍵の漏洩後の偽造** | 秘密鍵を持つ者は、世界中のどの検証実装から見てもあなたと区別がつかない。 |
| **N4** | **公開鍵の差し替え**——攻撃者が埋め込まれた公開鍵を自分のものに置き換え、任意の payload に自分の鍵で署名し直す | 信頼の起点は、攻撃者が編集できるファイルの中の 32 バイトの値にすぎない。 |
| **N5** | **時刻の改竄**——システムクロックを巻き戻して `exp` を回避する | オフラインの仕組みには信頼できる時刻源が存在しない。 |

## 5. 防げないこと——詳細・緩和策・その緩和策の限界

以下はいずれも解決策ではありません。それぞれ**緩和策**です。攻撃のコストや見返りを、測定できない量だけ変化
させるにとどまり、脅威そのものは残ります。ここに列挙するのは、正規ユーザーに与える不利益と釣り合うかどうか
をあなた自身が判断できるようにするため、そして自分の製品の文書で正確に説明できるようにするためです。

### N1 — バイナリ改変で検証が外される

*緩和策.* 検証実装を 1 か所ではなく複数から呼び、単一の真偽値ではなく payload の値に実際の挙動を依存させる
——`feat` から機能セットを導出し、`seats` から上限を導出する。こうすれば、1 つの分岐を削っただけでは「解錠
された版」ではなく「明らかに壊れた版」ができる。加えて更新を頻繁に出し、改変版が陳腐化して継続的な手間を
要するようにする。
*限界.* いずれも攻撃コストを測定できない量だけ引き上げるだけで、攻撃を取り除きはしない。ビルド *n* を改変
する意志のある攻撃者はビルド *n+1* も改変する。本キットは難読化もアンチデバッグも意図的に同梱していない
（本キットの非目標である）。それらは保護そのものより「保護されている感覚」を売る側面が大きいからである。
この点は検証がローカルであってもサーバー相手であっても変わらない。検証をオンラインに移しても、それは攻撃者
がすでに掌握しているバイナリの中のもう1つの分岐にすぎないからである（§6）。

### N2 — 正規購入者がキーを他人に共有する

*緩和策.* (a) **失効リスト**をアプリケーションに同梱し、公開されているのを見つけたキーの `lid` を
失効させ、通常のリリースに載せて更新配布する。(b) キーを**マシンフィンガープリントに紐付け**、1 つのキーが
多数のマシンで動かないようにする。(c) `sub` に購入者の識別子を入れ、`seats` を実態に合わせて設定し、流出
したキーが流出元をたどれるようにする。
*限界.* 失効リストはそれを載せた更新をインストールしたユーザーにしか届かないため、失効は常に後追いであり、
更新をやめたユーザーには決して届かない。**本キットが書き出す失効リストには署名が付いていない**ので、その
信頼性は「それを同梱したアプリケーションのバンドル」と同じ水準でしかない。自分で管理していない経路から
実行時に取得してはいけない——中間者が空のリストを返せてしまう（有料キットに同梱の `docs/revocation.md` §5
を参照）。
マシン紐付けは、再インストールする・ハードウェアを買い替える・
2 台で作業する正規ユーザーに不利益を与える。実際には、支払っている顧客からのサポート負荷を生みつつ、共有
したい者はパッチ済みビルドを渡せば済んでしまう。追跡可能性は共有を思いとどまらせることはあっても、阻止は
しない。
*本キットに含まれないもの.* 上記 3 つのうち実装されているのは (a) と (c) だけである——CLI は台帳を持ち失効
リストを書き出し、`sub`・`seats` は署名対象の payload に含まれる。マシン紐付け (b) は提供していない。`seats` は
情報用のフィールドであり検証実装は強制しない（`spec/key-format.md` §3）。フローティング／同時使用数ライセンスは
非目標である——サーバーなしに「今何本が同時に使われているか」は数えられない。有料キット同梱の `README.md`
§7（「LicenseSmith がしないこと」）に一覧がある。

### N3 — 秘密鍵が漏洩する

*緩和策.* 新しい鍵ペアを生成し、新しい公開鍵をアプリケーションの更新で配布し、既存の購入者にキーを再発行
する（CLI のバッチ発行はこの用途も想定している）。秘密鍵はオフラインで保管し、バックアップを取り、リポジ
トリにコミットしない。
*限界.* すでにインストールされているアプリケーションのコピーは、古い公開鍵を信頼し続け、それらを回収する
手段はない。漏洩した秘密鍵で偽造されたキーは、それらのビルドが使われ続ける限り受理され続ける。オフラインの
仕組みには、危殆化した署名鍵の失効経路が存在しない。事後にコストを打ち切れない唯一の失敗であり、だからこそ
鍵の保管は上記のどの対策よりも注意を払う価値がある。

### N4 — 公開鍵を差し替えて再署名される

*緩和策.* リリースに発行者の同一性が伴う経路——OS のコード署名、プラットフォームのストア、自分のドメインで
公開するチェックサム——を通じて署名・配布し、再署名されたビルドが、確認する気のあるユーザーには少なくとも
あなたのものと区別できるようにする。
*限界.* これが守るのは配布経路とあなたの評判であり、改変版を意図せず実行してしまうユーザーに対して意味を
持つ。改変版を承知の上でインストールするユーザーに対しては何の効果もない。また N4 は N1 と同じ能力を必要と
するため、片方ができる攻撃者は両方できる。N4 が特に問題になるのは、自分のコピーを解錠するだけでなく「動く
ビルド」を他人に再配布したい場合である。

### N5 — システムクロックを巻き戻される

*緩和策.* (a) アプリケーションがこれまでに観測した最大のタイムスタンプをローカルに記録し、それより前の時刻
を読んだ場合は疑わしいものとして扱う（単調増加の高水位マーク）。(b) 買い切り製品では `exp` より
`upd`——アップデート受給期限——を優先し、時間とともに失われる価値を「実行できること」（相手のクロックに依存
する）ではなく「新しいバージョンを受け取れること」（あなたが配布するので、あなたが制御できる）に置く。
*限界.* 高水位マークはローカルの状態であり、それを書いたバイナリとまったく同程度に編集可能で、プロファイル
を新規作成したりクリーンインストールしたりすればリセットされる。クロックが狂っていた・時刻設定をまたいで
移動した・バックアップから復元した、といった正規ユーザーに対して誤作動もする。`upd` は強制ではなく動機の
形を変えるだけであり、そもそも更新を受け取らないユーザーには効かない。

## 6. なぜオフラインなのに売り物になるのか

以下は安心材料ではなく、事実の列挙です。判断はあなた自身が行ってください。

1. **あなたのソフトウェアを使う人の多くは、支払いが容易で価格が妥当なら支払う。** ライセンスキーの仕事は、
   支払う経路を既定にし、支払わない経路を意識的な行為にすることであって、支払わない経路をなくすことでは
   ない。最後の数パーセントのユーザーを狙った対策は、回収できる売上よりも、サポート負荷と正規顧客に与える
   摩擦のほうが高くつく傾向がある。

2. **バイナリを改変する意志のある攻撃者は、オンライン検証も同様に無効化する。** ネットワーク検証も同じ
   バイナリの中の 1 つの分岐にすぎない。取り除く難度はローカルの署名検証を取り除くのと変わらず、実際には
   容易なことすらある——応答を偽装する、`hosts` でホスト名を書き換える、失敗時に通過する挙動にする、など。
   オンライン検証が引き上げるのはカジュアルなキー共有に対する敷居であって、バイナリ改変に対する敷居では
   ない。攻撃者がすでに掌握している場所に置かれているからである。

3. **サーバーにできてオフラインにできない唯一のことは、キー共有の「検出」である。** 同じキーが多数の
   インストールから照会されてくる、という事象の検出。語に注意すること——事後の検出であって、防止ではない。
   しかもそれは完璧ではない。NAT や VPN は多数のユーザーを 1 つのアドレスに畳み込むし、1 人の正規顧客が
   ノート PC とデスクトップと仮想マシンを持つのは日常である。オフラインのユーザーはそもそも何の信号も出さ
   ない。そして、どこに閾値を置いても、いずれ支払っている顧客を海賊版利用者として告発することになる。共有
   検出は実在する能力だが、相応のコストを伴うものであって、無条件の勝ちではない。

4. **サーバー検証は無料ではない。** 遅くなったり落ちたりし得る実行時依存が増え、一度売った製品の寿命の間
   ずっと毎月の請求が続き、プライバシー上の面（誰がいつあなたのソフトウェアを動かしたかを記録することに
   なる）が生まれ、決済プラットフォームを移行するたびに壊れる構成要素を抱えることになる。

オフライン検証は共有検出を手放します。その代わり、停止することがなく、アプリケーションの起動に遅延を足さ
ず、運用費がかからず、決済事業者が買収・停止されても動き続け、ネットワークのないユーザーでも使えます。

## 7. 自分のユーザー向け・出品ページ向けの推奨表現

仕組みが持つ以上のことを主張しないでください。正確な表現は、懐疑的な読み手に晒されても崩れない表現でもあり
ます。

> ライセンスはローカルで Ed25519 署名により検証されます。これにより、お使いのキーが当方が発行したもので
> あり、改変されていないことを確認します。外部への通信は行わず、お客様に関する情報も収集しません。

本製品に限らず、ライセンス保護の仕組みを絶対的な言い回しで説明することは避けてください。本キットの
`README.md` と出品ページも、下の付録に記録した同じ自己チェックの対象です。

---
---

<!-- OVERCLAIM-SELFCHECK-START -->

# Appendix A — Overclaim self-check record / 付録A — 誇大表現の自己チェック記録

**This appendix is excluded from the search described below, because it necessarily contains the search
terms themselves.** The search covers everything above the `OVERCLAIM-SELFCHECK-START` marker — that is,
the entire English and Japanese body of this document.

**この付録自体は、下記の検索の対象外です。検索語そのものを含まざるを得ないためです。** 検索範囲は
`OVERCLAIM-SELFCHECK-START` マーカーより上のすべて——本文書の英語本文と日本語本文の全体です。

Date / 実施日: 2026-09-07
Target / 対象: `spec/threat-model.md` (body only / 本文のみ)

Command actually run / 実際に実行したコマンド:

```sh
sed '/OVERCLAIM-SELFCHECK-START/,$d' spec/threat-model.md > body.txt
grep -n -i -F -f terms.txt body.txt ; echo "exit=$?"
```

Search terms and results / 検索語と結果:

| # | Term / 検索語 | Hits / 件数 |
|---|---|---|
| 1 | `unbreakable` | 0 |
| 2 | `uncrackable` | 0 |
| 3 | `crack-proof` | 0 |
| 4 | `hack-proof` | 0 |
| 5 | `tamper-proof` | 0 |
| 6 | `tamperproof` | 0 |
| 7 | `bulletproof` | 0 |
| 8 | `foolproof` | 0 |
| 9 | `100% secure` | 0 |
| 10 | `completely secure` | 0 |
| 11 | `totally secure` | 0 |
| 12 | `perfectly secure` | 0 |
| 13 | `impossible to crack` | 0 |
| 14 | `cannot be cracked` | 0 |
| 15 | `guaranteed protection` | 0 |
| 16 | `military-grade` | 0 |
| 17 | `クラック不可` | 0 |
| 18 | `クラック不能` | 0 |
| 19 | `破られない` | 0 |
| 20 | `破られません` | 0 |
| 21 | `完全に安全` | 0 |
| 22 | `絶対に安全` | 0 |
| 23 | `絶対安全` | 0 |
| 24 | `100%安全` | 0 |
| 25 | `解析不能` | 0 |
| 26 | `解読不能` | 0 |
| 27 | `改造不可` | 0 |
| 28 | `突破されない` | 0 |
| 29 | `鉄壁` | 0 |
| 30 | `万全` | 0 |

**Total hits: 0. `grep` exit status 1 (no lines selected).**
**合計 0 件。`grep` の終了ステータスは 1（該当行なし）。**

Notes / 補足:

- The words *authenticity*, *integrity*, *真正性*, *完全性* do appear in the body. They are scoped technical
  terms describing exactly what a signature check establishes, and they are qualified in §1 by an explicit
  statement of what is not covered.
  本文には *authenticity*・*integrity*・真正性・完全性 が現れます。これらは署名検証が確立する事柄を正確に
  指す限定的な技術用語であり、§1 で「何が対象外か」を明示することで限定されています。
- The word *infeasible* appears once (§4.1 P1) as the standard cryptographic term for the hardness
  assumption underlying Ed25519. It is not a claim about this product.
  *infeasible*（計算量的に困難）は §4.1 P1 に 1 回現れます。Ed25519 が依拠する困難性仮定を指す暗号学の標準
  用語であり、本製品についての主張ではありません。
- Numerical claims in this document are limited to the four Ed25519 properties in §2 (≈128-bit security
  level, 64-byte signature, 32-byte public key, deterministic signing). No other figures are stated.
  本文書の数値的主張は §2 の Ed25519 の 4 性質（約128ビット相当、署名64バイト、公開鍵32バイト、決定論的
  署名）に限られます。それ以外の数値は記載していません。
- The same check is repeated against `README.md` and the store listing text before each release. If you
  reuse wording from this document in your own product's listing, run the same search over that text too.
  同じチェックは、各リリースの前に `README.md` と出品ページ本文に対しても実施しています。本文書の表現を自分の
  製品の出品ページに転用する場合は、その文章にも同じ検索を掛けてください。
