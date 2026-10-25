# cage: подписанные версии, явное расширение доступа (`-grant`), код выхода 3

Самостоятельный план реализации. Репозиторий: `github.com/themakers/cage`
(Go, `libcage/`, `libssh/`, CLI в корне, Nix-модуль в `nix/`).

---

## 1. Проблемы

### P1. Доступ расширяется молча через `cage.yaml`

`EncryptAll` (`libcage/encrypt.go`) берёт получателей каждого секрета только
из текущего `cage.yaml` (`buildRecipientPlan`: объединение `recipients` всех
env, ссылающихся на файл). Секрет перешифровывается, когда отличается список
получателей, даже если значение не менялось. `EncryptAll` проходит по **всем**
секретам с локальным plaintext, и его запускают также `set`, `mv`, `rm`,
`import`, `comment`, `keygen`. Предупреждений нет (только `Info: encrypted …
recipients=N`).

Атака: пользователь с правом записи в репозиторий добавляет свой ключ в
группу, подменяет чужой ключ своим (число получателей не меняется) или
добавляет свой env поверх чужих файлов. Тот, кто имеет расширенный доступ,
делает `pull` и любой `encrypt` — секреты шифруются и для атакующего.

### P2. Нет проверки автора версии

age не аутентифицирует отправителя. Любой, кто может писать в репозиторий,
создаёт полностью валидный store-файл: подменяет значение (например, `DB_URL`
на свой сервер) для законных получателей, и `decrypt` принимает его как
обычное изменение. Отозванный получатель, знающий текущее значение, может
вернуть себя в список любым способом, который опирается на знание plaintext
(поэтому HMAC от plaintext отвергнут: он требует обязательной ротации при
каждом отзыве, а это неприемлемо для DX).

### P3. Откат и подмена истории

`history` (список SHA значений) не фиксирует смену получателей: отзыв без
ротации не оставляет следа. Store-файл можно откатить к подлинной версии до
отзыва, и рабочая копия не отличит это от актуального состояния.

### P4. Серверы и CI без памяти

`cage credentials prepare` (`libcage/credentials.go`) принимает любой файл,
который расшифровывается ключом машины; состояния у него нет (ramfs,
`ProtectSystem=strict`). CI обычно деплоит из свежего клона. Оба — «первое
доверие» на каждом запуске: фабрикация и откат значения не обнаруживаются.

### P5. Агент повторяет команды

LLM-агент, получив ошибку, склонен «починить» её и повторить. Если выход из
отказа — флаг, агент добавит флаг сам. Нужен отдельный, узнаваемый сигнал.

---

## 2. Решения

### S1. Подписанный DAG версий в store-файле

Каждая версия — заголовок (родители, автор, fingerprints получателей, хэши
plaintext и payload), подписанный SSH-ключом автора (`sshsig`). Заголовки
накапливаются в файле (`versions`), payload хранится только у head.
Правило авторства: версию с родителями P₁…Pₙ может подписать только
получатель **каждого** родителя (genesis — получатель самого себя).

### S2. Исходный список получателей = получатели родителя

Для `-grant` исходный список берётся из проверенного родителя: у слияния —
**пересечение** родителей (отзыв в любой ветке побеждает), у genesis — пусто
(все получатели требуют `-grant`). MAC не нужен: список защищён подписью и
не зависит от знания значения.

### S3. `-grant` — явное согласие, код выхода 3

Новые ключи сверх исходного списка → `encrypt` отказывает, ничего не пишет,
перечисляет все пункты во всех секретах, завершает с кодом 3. Продолжить
можно только `cage encrypt -grant <ref>=<fingerprint> …` с точным набором.
Удаление получателя — Warn на каждую пару с советом ротировать, не блокирует.

### S4. База рабочей копии — якорь доверия

`.cage/local/base` уже хранит байтовую копию принятого store-файла, то есть
весь журнал. Новая версия из store принимается, если цепочка верна и имеет
общего предка с базой: потомок — обычное обновление; предок/ответвление —
слияние (обе стороны подлинны); нет общего предка — ошибка целостности,
код 3. Свежий клон — первое доверие (как `known_hosts`).

### S5. Серверы: закреплённые подписанты, без состояния

Манифест `credentials` получает обязательное `signers` — файл публичных
ключей, доставляемый тем же каналом, что identity. `prepare` проверяет
цепочку и что head подписан ключом из файла. Откат к подлинной старой версии
на decrypt-only сервере — не утечка (стейл-значение / DoS), принимается.

### S6. `cage verify` для CI и аудита

Проверяет все store-файлы и compiled envs без identity. `-signers file` —
закреплённые подписанты; `-base dir` — внешняя база (CI с памятью),
продвигается после успеха. Код 3 при нарушении.

### S7. Окно версий: автоматическая обрезка хвоста

`encrypt` сохраняет только заголовки, достижимые от head на глубину ≤
`VersionWindow` (100, преемник `HistoryLimit`). Заголовки, чьи родители
выпали, — **checkpoint-заголовки**: у них проверяются подпись и `id`, но не
авторство. Легитимность точки отреза удостоверяет база проверяющего (её
`id` есть в журнале базы) либо первое доверие. Это модель «слабой
субъективности»: копия, отставшая больше чем на окно, получает код 3 и
начинает заново явным действием (`rm .cage/local/base/<файл>`, `decrypt`).
Размер файла почти фиксирован: K × (~200 Б + ~50 Б/получатель + ~150 Б
подпись).

### S8. Правила для агента в `skill.md`

Код 3 — агент не повторяет команду и не добавляет `-grant`/флаги сам, а
показывает оператору полный список пунктов и ждёт решения.

---

## 3. Модель угроз и компромиссы

### Допущения

- Атакующий может писать в репозиторий и в любой транспорт (git, флешка).
- Атакующий **не** может деплоить на сервер и не владеет приватными ключами
  честных получателей. Сервер полностью доверяет своему деплоеру (тот ставит
  identity, бинарник, юниты) — это граница, которую cage не сдвигает.
- git — только транспорт; никакой анализ git-истории в требования не входит.

### Гарантии

| Свойство | Чем достигается | Чему приходится доверять |
|---|---|---|
| Секрет не прочтёт не-получатель | age | Только криптографии |
| Доступ не расширится молча | подписи + `-grant` | Честности того, кто шифрует, и его базе |
| Значение не подменит не-получатель | подписи, правило авторства | Якорю проверяющего: база (TOFU) или `signers` |
| Отозванный не вернёт себя без ротации | правило авторства (нет в получателях родителя) | То же |
| Откат / форк обнаруживается | DAG + база | Тому, у кого есть база, видевшая более новую версию |
| Серверу не подсунут сфабрикованную версию | `signers` | Каналу доставки `signers` (= каналу identity) |

### Что остаётся (документируется явно)

1. **Свежесть без состояния недостижима** (SUNDR, Mazières & Shasha, 2002).
   Потолок без доверенной стороны с памятью — fork consistency: копия,
   не видевшая отзыва, примет ветку отозванного; расхождение обнаружится у
   первого, кто увидит обе ветки (при слиянии пересечение исключает
   атакующего → `-grant`). CI без `-base` и без ревью свежести не даёт.
2. **Каждый читатель — писатель.** Получатель может подменить значение.
   Отдельная роль «писатель» не вводится.
3. **Откат на сервере** (подлинная старая версия, подписанная закреплённым
   ключом): не утечка; стейл-значение или падение сервиса после ротации.
4. **Runtime-источники** (`/var/lib/...`) вне `verify`; целостность — на
   канале доставки.
5. `plaintext_sha256` в открытом виде позволяет офлайн подбирать слабые
   секреты. Отдельная тема, не в этом плане.
6. Компрометация приватного ключа получателя = компрометация секретов до
   ротации. Неизбежно.

### Компромиссы

- `encrypt` теперь требует identity (подпись). Раньше шифровал без ключа.
- Журнал ограничен окном в `VersionWindow` версий (~60 КБ при K=100 и пяти
  получателях; git-diff на `encrypt` — один заголовок добавлен, один
  удалён). Обратная сторона: копия, не синхронизировавшаяся дольше окна,
  должна явно начать заново. Обрезка не ослабляет схему: отрез до версии до
  отзыва — тот же откат (общий предок есть, слияние с пересечением исключает
  атакующего), отрез до сфабрикованной точки — код 3.
- Каждый новый ключ подтверждается один раз явно. Это и есть цель.
- Старый формат не поддерживается: один переход, все обновляются заранее.
- `sk-`/agent-ключи не поддерживаются и сейчас; ничего не меняется.
- Защита от отката на сервере не делается (ломала бы `nixos-rebuild
  --rollback`, падала без оператора, ключ отметки выбирал бы атакующий).

---

## 4. Карта реализации

### 4.1 `libssh/sshsig.go` — подпись и проверка

- Формат `PROTOCOL.sshsig` (OpenSSH): blob `"SSHSIG"‖u32 version=1‖string
  publickey‖string namespace‖string reserved‖string hash_alg‖string
  signature`; подписывается `"SSHSIG"‖namespace‖reserved‖hash_alg‖H(msg)`.
  namespace `"cage"`, hash `sha512`. RSA — `rsa-sha2-512`
  (`ssh.AlgorithmSigner`). Armor PEM `SSH SIGNATURE`, строки по 70.
- API: `Sign(signer ssh.Signer, namespace string, msg []byte) (string, error)`;
  `Verify(armored, namespace string, msg []byte) (ssh.PublicKey, error)`
  (возвращает ключ из подписи).
- Тест: round-trip ed25519/rsa; если в PATH есть `ssh-keygen`, сверка
  `ssh-keygen -Y sign` ↔ `Verify` и `Sign` ↔ `ssh-keygen -Y verify`.

### 4.2 `libcage/formats.go` — формат

- `SecretBody`: удалить `History`; добавить `Versions []VersionHeader`.
- `VersionHeader{ID, Parents []string, Author string, Recipients []string
  (fingerprints), PlaintextSHA256, PayloadSHA256, Signature string}`.
- Канонический байтовый вид заголовка без `Signature`: JSON со
  структурно фиксированным порядком полей (`encoding/json` над struct) —
  `ID = sha256hex(canon)`; та же `canon` — сообщение для подписи.
- `MarshalSecretStable`: добавить `versions`; `payload` как литерал, как
  сейчас. `ParseSecretV1`: разбор `versions`; `HistoryLimit` удалить.
- Fingerprint: `ssh.FingerprintSHA256` (формат `SHA256:…`), общий хелпер
  `FingerprintOfKeyLine(line string) (string, error)`.

### 4.3 `libcage/chain.go` — проверка цепочки (новый файл)

- `verifySecretFile(s *SecretV1) (*chain, error)`:
  - `versions` непусто; `id` каждого пересчитан; родители либо стоят
    раньше в списке (топологический порядок), либо отсутствуют —
    тогда заголовок checkpoint; ровно один head (последний; все остальные —
    чьи-то родители);
  - подпись верна, ключ подписи имеет fingerprint `author`;
  - `author ∈ recipients(parent)` для всех **присутствующих** родителей;
    genesis (`parents: []`): `author ∈ recipients(self)`; checkpoint —
    авторство не проверяется;
  - head: `payload_sha256 == sha256(DecodePayload(payload))`,
    `plaintext_sha256` совпадает с верхним, fingerprints(top-level
    `recipients`) == head.recipients.
- `chain` даёт: `Head() *VersionHeader`, `IsAncestor(a, b string) bool`,
  `Has(id string) bool`, `Checkpoints() []string`, `Baseline(parents)`
  (пересечение получателей **присутствующих** родителей; для genesis —
  пусто; выпавший из окна родитель игнорируется: автор слияния и так обязан
  быть получателем присутствующего).
- `acceptAgainstBase(store, base *chain) error`: общий предок = `id`,
  присутствующий в обоих журналах; есть → заголовки store после него
  проверены полностью (см. выше), до него — только подпись и `id`;
  нет (и база есть) → `SecurityError{Integrity, "no common version with
  the accepted history"}`; базы нет → первое доверие.
- `prune(headers, VersionWindow)`: оставить достижимые от head на глубину
  ≤ K, в топологическом порядке; вызывается перед записью в `encrypt`.
- Ошибки: `*SecurityError{Kind: Integrity, …}` с именем секрета и причиной
  (без значений).
- Проверка compiled env: каждая вложенная `SecretV1` проверяется так же.

### 4.4 `libcage/security.go` — типизированная ошибка, код 3

- `type SecurityError struct{Kind SecurityKind; Msg string}`;
  `SecurityKind ∈ {GrantRequired, Integrity}`; `Error()`; `Unwrap` не нужен.
- `main.go: exitErr`: `errors.As(err, *SecurityError)` → `os.Exit(3)`;
  сообщение выводится как сейчас (`error: …`). Константа `ExitSecurity = 3`.
- `cmd_run.go` пробрасывает код дочернего процесса — не трогать.

### 4.5 `libcage/local.go` + `sync.go` — база и состояние

- `version`: `SHA`, `File`, `Raw`, `Chain *chain` (вместо `History`).
  `parseVersion` вызывает `verifySecretFile`; ошибка целостности — как
  есть, наверх.
- База без `versions` (старый формат) → `readBase` возвращает `nil` и
  пишет `Info: discarding pre-signature base` (один переход после
  обновления).
- `syncState`: `in.S.has(in.B.SHA)` → `in.S.Chain.IsAncestor(B.head.id,
  S.head.id)`; `Older` → `in.B.Chain.IsAncestor(S.head.id, B.head.id)`;
  новый случай: `B != nil && S != nil && !commonAncestor(B,S)` →
  `SecurityError{Integrity, "store history was replaced"}`.
- `commonAncestor` (decrypt.go): выбор предка — по DAG (`IsAncestor`), не
  по `has(SHA)`.
- `setBase`/`.prev` — без изменений.

### 4.6 `libcage/encrypt.go` — `-grant`, подпись, warn

- Сигнатура: `EncryptAll(opts EncryptOptions)`, `EncryptOptions{Grants
  map[SecretRef][]string /* fingerprints */}`.
- Фаза 1 (проверка, ничего не пишется) дополняется:
  - для каждого секрета с изменением (значение или получатели): исходный
    список = `S.Chain.Baseline…` — точнее, получатели родителей новой
    версии: `[S.head]` обычно; при слиянии (`B.head ≠ S.head` и B не предок
    S — после merge decrypt уже поставил base := S, так что родители
    определяются по `.prev`: если `B.prev` существует и не предок `S` →
    родители `[S.head, B.prev.head]`); для `local-only` — пусто;
  - `added = new − baseline` (по fingerprint), `removed = baseline − new`;
  - для каждого `added` без grant → пункт отказа; каждый grant, которого нет
    в `added` → ошибка «grant not needed»; 
  - выбор подписывающей identity: `c.Ids.SSH` с `PublicKey`, чей fingerprint
    ∈ получателей всех родителей (genesis: ∈ новых); нет → ошибка
    «no identity may sign <ref>: signer must already be a recipient».
- Отказ (код 3), формат:
  ```
  encrypt refused: new recipients need explicit grant (nothing written)
    ops:db.env
      SHA256:abc…  comment "mallory@laptop" (untrusted, from the key line)
        via env ops → group devops
    ops:api.env
      SHA256:abc…  …
  Verify every fingerprint with its owner over a separate channel.
  To proceed exactly as listed:
    cage encrypt -grant ops:db.env=SHA256:abc… -grant ops:api.env=SHA256:abc…
  ```
  Путь `env → группа` берётся из обхода `ResolveRecipientRefs` (добавить
  вариант, возвращающий путь: `ResolveRecipientPaths`).
- Warn на удаление (не блокирует):
  `WARN recipient removed secret=ops:db.env key=SHA256:… comment=… — the
  holder still knows the current value; rotate it when that matters`.
- Фаза 2: заголовок новой версии (`parents`, `author`, fingerprints,
  хэши), подпись, `prune` до `VersionWindow`, запись; `setBase`. Версия не создаётся, если ни значение,
  ни получатели не изменились (как сейчас).
- `compileEnv` — без изменений по сути (встраивает `SecretV1` с журналом).

### 4.7 Команды

- `cmd_encrypt.go`: флаг `-grant` (повторяемый, `ref=fingerprint`); парсинг
  → `EncryptOptions`.
- `cmd_edit.go` (общий `encryptAfterEdit`): вызывает `EncryptAll` без
  grants; `SecurityError{GrantRequired}` оборачивается: «plaintext is already
  changed; `cage encrypt -grant …` publishes it together with the grants».
- `cmd_verify.go` (новый): `cage verify [-signers file] [-base dir]`:
  - обходит `.cage/store/files/**` и `envs/**`, `verifySecretFile`;
  - в cage-root без `-base` сверяет с `.cage/local/base` (общий предок);
  - с `-base dir` — сверяет с `dir/<rel>` и после полного успеха копирует
    store-файлы туда (атомарно, по файлу);
  - с `-signers` — head каждого секрета подписан ключом из файла;
  - вывод: по секрету `ok  ops:db.env  v=<id[:12]> by SHA256:…`; любая
    ошибка → список и код 3. Identity не требуется.
- `cmd_credentials.go` / `libcage/credentials.go`: `CredentialsManifest.
  Signers string` (обязателен, `isCleanAbs`); `ComposeCredentials` после
  чтения каждого файла — `verifySecretFile` + проверка head.author ∈
  signers; ошибка → `SecurityError{Integrity}`.
- `run -raw`, `dump` по путям, `decrypt_raw`: читать через общий
  `loadCageFile(path) (secrets []SecretV1)` с `verifySecretFile`;
  флаг `-signers` у `run`/`dump` (опционально).
- `inspect`/`status`: показывать `version <id[:12]> by <author fp>`,
  число версий; в `syncHint` — новые состояния.
- `usage.go`: `verify`, `-grant`, `-signers`; код выхода 3 в шапке.

### 4.8 Читатели store — единая точка

Все места из `grep ParseSecretV1|ParseEnvironmentV1|readStoreVersion`
(`dump.go:151,161`, `run_env.go:194,207`, `decrypt_raw.go:44,55`,
`inspect.go:269`, `edit.go:58`, `read_secret.go:13`, `sync.go:52`,
`encrypt.go:157`) переводятся на `readStoreVersion`/`loadCageFile`, которые
проверяют цепочку. Прямые вызовы `ParseSecretV1` остаются только внутри них.

### 4.9 Nix и инфраструктура

- `nix/module.nix`: опция `cage.signersFile` (string, обязательна при
  `enable`; не Nix-путь); в манифест — `signers`.
- `nix/tests/fixtures.sh`: `encrypt` → `encrypt -grant …` (fingerprints
  через `ssh-keygen -lf`); генерировать `signers` файл; негативные фикстуры:
  файл с подменённым payload, файл с подписью не из `signers`.
- VM-тест (`nix/tests/credentials.nix`): новые случаи — отказ на поддельный
  файл и на чужого подписанта; код 3 преparer'а в journal.
- `Makefile`/CI: без изменений, кроме прогонки новых тестов.

### 4.10 Документация

- `README.md`: раздел **Trust model** (таблица из §3), обновлённый
  **Working together** (`-grant`, warn о ротации, `verify`, код 3),
  миграция (один `encrypt -grant` на всё; остальные `decrypt`).
- `skill.md`: правило для агента (код 3 → не повторять, не добавлять флаги,
  показать оператору весь список, ждать); `-grant` синтаксис; `verify` в
  чек-листах; смысл warn об удалении; окно версий и что делать копии,
  отставшей больше чем на окно (явный сброс базы — только по решению
  оператора).
- `skill_infra.md`: `signers` в манифесте и модуле, доставка как identity;
  CI: `verify -signers`/`-base` либо ревью; runtime-источники вне `verify`;
  откат на сервере — не утечка.

### 4.11 Тесты (Go)

- `libssh/sshsig_test.go` — см. 4.1.
- `libcage/chain_test.go`: валидная цепочка; подделанная подпись; автор не
  получатель родителя; `payload` подменён; fingerprints не совпадают с
  `recipients`; неподписанный файл; откат (store — предок базы) → diverged,
  не ошибка; форк → слияние с пересечением; другой genesis → Integrity;
  обрезка: окно ровно K после K+5 версий, checkpoint принят копией, у
  которой точка отреза есть в базе; копия старше окна → Integrity;
  атакующий отрезал до версии до отзыва → слияние, пересечение без него;
  слияние с выпавшим родителем → baseline по присутствующему.
- `libcage/encrypt_test.go`: grant required (пункты, текст команды); grant
  принят; лишний grant; genesis требует всех; слияние: пересечение; warn
  при удалении; нет подписывающей identity.
- `sync_test.go`, `credentials_test.go`, `llm_test.go`: адаптация к
  формату; `credentials`: `signers` обязателен, чужой подписант → код 3.
- `main` уровня: таблица «ошибка → код выхода» (1 / 2 / 3).

### 4.12 Порядок работ

1. `sshsig` + тесты.
2. Формат + `chain.go` + `SecurityError` + тесты цепочки.
3. `local/sync/decrypt` на DAG; `sync_test`.
4. `encrypt` (`-grant`, подпись, warn) + `cmd_encrypt`/`cmd_edit`; тесты.
5. Единая точка чтения (`run`, `dump`, `inspect`, `raw`).
6. `verify`, `credentials.signers`, Nix-модуль, фикстуры, VM-тест.
7. README, skill, skill_infra, usage.
8. Прогон: `go test ./...`, `nix flake check`.

### 4.13 Миграция (разовая)

Все обновляют cage. Админ: `cage decrypt` (база старого формата
отбрасывается), `cage encrypt -grant …` на все пары (команда в отказе
печатает их готовыми). Остальные: `cage decrypt`. Серверы: доставить
`signers`, задать `cage.signersFile`, перевыкатить.
