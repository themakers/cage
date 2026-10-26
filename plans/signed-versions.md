# cage: подписанные версии, явное расширение доступа (`-grant`), код выхода 3

Самостоятельный план реализации. Репозиторий: `github.com/themakers/cage`
(Go, `libcage/`, `libssh/`, CLI в корне, Nix-модуль в `nix/`).

Вторая редакция: линейная цепочка вместо DAG, грант по ключу, один
sidecar `.fork`, привязка заголовка к имени, подписанные компилированные
env, legacy-путь миграции. Обоснование упрощений — в §3.4.

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

### P3. Откат, подмена истории и пересадка файлов

`history` (список SHA значений) не фиксирует смену получателей: отзыв без
ротации не оставляет следа. Store-файл можно откатить к подлинной версии до
отзыва, и рабочая копия не отличит это от актуального состояния. Подлинный
файл одного секрета можно положить на место другого (`dev:db.env` →
`ops:db.env`, компилированный `envs/dev.cage` → `envs/ops.cage`): значение
законное, место — нет.

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

### S1. Подписанная линейная цепочка версий в store-файле

Каждая версия — заголовок (`ref` секрета, родитель, автор, fingerprints
получателей, хэши plaintext и payload, время), подписанный SSH-ключом автора
(`sshsig`). Заголовки накапливаются в файле (`versions`, старые первыми,
head последний), payload хранится только у head. Родитель ровно один (у
genesis — нет). Правило авторства: версию с родителем P может подписать
только получатель P; genesis — получатель самого себя.

### S2. Исходный список получателей = получатели родителя

Для `-grant` исходный список берётся из проверенного родителя (head store).
Если рабочая копия пережила форк (store не потомок базы), исходный список —
**пересечение** с получателями базы на момент форка (sidecar `.fork`, S4).
У нового секрета исходный список — ключи, которые эта рабочая копия уже
приняла в любом секрете (объединение получателей голов всех её баз); у
свежего клона — пусто. MAC не нужен: список защищён подписью и не зависит от
знания значения.

### S3. `-grant` — явное согласие, код выхода 3

Ключи сверх исходного списка → `encrypt` отказывает, ничего не пишет,
перечисляет ключи и секреты, завершает с кодом 3. Продолжить можно только
`cage encrypt -grant <fingerprint> …` с точным набором ключей; грант
действует на все секреты прогона (какие именно — показано в отказе и задано
`cage.yaml`, который оператор правил сам). Удаление получателя — Warn на
каждую пару с советом ротировать, не блокирует.

### S4. База рабочей копии — якорь доверия

`.cage/local/base` уже хранит байтовую копию принятого store-файла, то есть
весь журнал. Новая версия из store принимается, если цепочка верна и имеет
общий `id` с базой: потомок — обычное обновление; предок/форк — слияние
(обе стороны подлинны), при этом база на момент форка сохраняется в `.fork`
до следующей успешной публикации; нет общего `id` — ошибка целостности,
код 3. Форк, в чьей ветке есть автор, не бывший получателем базы (только
отозванный может такое подписать), не сливается автоматически: store-версия
кладётся рядом (`<name>.store`, существующий путь конфликта). Свежий клон —
первое доверие (как `known_hosts`).

### S5. Серверы: закреплённые подписанты, без состояния

Манифест `credentials` получает обязательное `signers` — файл публичных
ключей, доставляемый тем же каналом, что identity, — и у каждого источника
обязательное `secret: "<dir>:<name>"` либо `env: "<name>"`. `prepare`
проверяет цепочку, привязку заголовка к ожидаемому `ref`/env и что **каждая**
подпись, на которую он опирается (head секретов, заголовок env), сделана
ключом из `signers`. Откат к подлинной старой версии на decrypt-only сервере
— не утечка (стейл-значение / DoS), принимается.

### S6. `cage verify` для CI и аудита

Проверяет все store-файлы и compiled envs без identity: цепочки, привязку,
соответствие env головам store, общий предок с базой рабочей копии.
`-signers file` — закреплённые подписанты. Код 3 при нарушении.

### S7. Окно версий: автоматическая обрезка хвоста

`encrypt` сохраняет только последние `VersionWindow` (50) заголовков. Самый
старый заголовок окна — **checkpoint**: у него проверяются подпись и `id`,
но не авторство (родителя нет). Легитимность точки отреза удостоверяет база
проверяющего (её `id` есть в журнале) либо первое доверие. Это «слабая
субъективность»: копия, отставшая больше чем на окно, получает код 3 и
начинает заново явным действием (`rm .cage/local/base/<файл>`, `decrypt`).
Размер файла почти фиксирован: K × (~600 Б + ~50 Б/получатель).

### S8. Правила для агента в `skill.md`

Код 3 — агент не повторяет команду и не добавляет `-grant`/флаги сам, а
показывает оператору полный список ключей и секретов и ждёт решения.

---

## 3. Модель угроз и компромиссы

### 3.1 Допущения

- Атакующий может писать в репозиторий и в любой транспорт (git, флешка).
- Атакующий **не** получатель и не владеет приватными ключами честных
  получателей. Получатель (инсайдер) может подменить значение и добавить
  ключ — линейно, подписав версию; это принимается осознанно (любой
  читатель и так может передать значение).
- Атакующий **не** может деплоить на сервер. Сервер полностью доверяет
  своему деплоеру (тот ставит identity, `signers`, бинарник, юниты).
- git — только транспорт; анализ git-истории в требования не входит.

### 3.2 Гарантии

| Свойство | Чем достигается | Чему приходится доверять |
|---|---|---|
| Секрет не прочтёт не-получатель | age | Только криптографии |
| Доступ не расширится молча | подписи + `-grant` | Честности того, кто шифрует, и его базе |
| Значение не подменит не-получатель | подписи, правило авторства | Якорю проверяющего: база (TOFU) или `signers` |
| Отозванный не вернёт себя без ротации | правило авторства + `.fork` при форке | То же |
| Откат / форк обнаруживается | цепочка + база | Тому, у кого есть база, видевшая более новую версию |
| Файл не пересадить на чужое место | `ref` в заголовке, подписанный env | Якорю проверяющего |
| Серверу не подсунут сфабрикованную версию | `signers` | Каналу доставки `signers` (= каналу identity) |

### 3.3 Что остаётся (документируется явно)

1. **Свежесть без состояния недостижима** (SUNDR, Mazières & Shasha, 2002).
   Потолок — fork consistency: копия, не видевшая отзыва, примет ветку
   отозванного; расхождение обнаружится у первого, кто увидит обе ветки.
   CI без базы и без ревью свежести не даёт.
2. **Каждый читатель — писатель.** Отдельная роль «писатель» не вводится.
   Для серверов роль писателя де-факто задаёт `signers`.
3. **Откат на сервере** (подлинная старая версия, подписанная закреплённым
   ключом): не утечка; стейл-значение или падение сервиса после ротации.
4. **Удаление секрета** (`rm -file`) не подписано: воскрешение старого
   подлинного файла ловит только база (нет общего предка — нет; предок есть
   — форк/откат, слияние с `.fork`).
5. `plaintext_sha256` в открытом виде позволяет офлайн подбирать слабые
   секреты. Отдельная тема, не в этом плане.
6. Компрометация приватного ключа получателя = компрометация секретов до
   ротации. Неизбежно.
7. `encrypt` со свежего клона (нет базы) для существующих секретов берёт
   исходный список из head store — первое доверие. Для новых секретов на
   свежем клоне гранты нужны на все ключи.

### 3.4 Что упрощено относительно первой редакции и почему

- **DAG → линейная цепочка.** Пересечение родителей было нужно ради одного
  случая — форка от отозванного получателя (инсайдер и так добавляет ключи
  линейно). Этот случай закрывает sidecar `.fork`: пересечение с базой на
  момент форка. Ушли merge-заголовки, импорт заголовков чужой ветки,
  топологический порядок, глубина на графе.
- **Грант по ключу, не по паре (секрет, ключ).** Оператор проверяет
  владельца ключа; какие секреты ключ получит — видно в отказе и задано
  `cage.yaml`. По-парная точность не добавляла решения, а усложняла флаг.
- **Новый секрет: «ключ новый, если его нет ни в одной принятой этой копией
  версии».** Ноль нового состояния; не-получатель ловится всегда; инсайдер
  проходит — по модели угроз. Иначе каждый `set` нового секрета — две
  команды.
- **Без `verify -base dir`, без `-signers` у `run`/`dump`, без списка
  доверенных ключей.** Не нужны для гарантий; добавляются при спросе.
- **Компилированные env несут только head** каждого секрета и собственный
  подписанный заголовок (вместо полного журнала каждого секрета).

### 3.5 Компромиссы

- `encrypt` теперь требует identity (подпись). Раньше шифровал без ключа.
  Подписать может только получатель: создать секрет, который сам не
  читаешь, нельзя.
- Журнал ограничен окном в `VersionWindow` версий. Копия, не
  синхронизировавшаяся дольше окна, должна явно начать заново. Обрезка не
  ослабляет схему: отрез до версии до отзыва — тот же откат (общий предок
  есть, пересечение с `.fork` исключает атакующего), отрез до
  сфабрикованной точки — код 3.
- Каждый новый ключ подтверждается один раз явно — на существующих
  секретах при каждом добавлении, на новых секретах — только если копия его
  ещё не принимала.
- Старый формат читают только `decrypt` и `encrypt` (миграция, §4.14);
  остальные команды отказывают. Legacy-ветка удаляется следующим релизом.
- `sk-`/agent-ключи и passphrase-ключи для подписи не поддерживаются (как и
  для расшифровки сейчас): age не умеет agent, и cage уже требует
  незашифрованный ключ в файле.
- Защита от отката на сервере не делается (ломала бы `nixos-rebuild
  --rollback`, падала без оператора, ключ отметки выбирал бы атакующий).

---

## 4. Карта реализации

### 4.1 `libssh/sshsig.go` — подпись и проверка

- Формат `PROTOCOL.sshsig` (OpenSSH): blob `"SSHSIG"‖u32 version=1‖string
  publickey‖string namespace‖string reserved‖string hash_alg‖string
  signature`; подписывается `"SSHSIG"‖string namespace‖string reserved‖
  string hash_alg‖string H(msg)`, hash `sha512`. RSA — `rsa-sha2-512`
  (`ssh.AlgorithmSigner`); ed25519 — `ssh-ed25519`; другие типы — ошибка
  (age их и не поддерживает). Armor PEM `SSH SIGNATURE`, строки по 70.
- Namespaces: `cage-version` (заголовок секрета), `cage-environment`
  (заголовок env).
- API: `Sign(signer ssh.Signer, namespace string, msg []byte) (string, error)`;
  `Verify(armored, namespace string, msg []byte) (ssh.PublicKey, error)`
  (возвращает ключ из подписи; namespace в подписи обязан совпасть).
- Тест: round-trip ed25519/rsa; подпись с чужим namespace отвергается; если
  в PATH есть `ssh-keygen`, сверка `ssh-keygen -Y sign` ↔ `Verify` и `Sign`
  ↔ `ssh-keygen -Y verify` (с временным `allowed_signers`).

### 4.2 `libcage/formats.go` — формат

- Kinds: `secret/v2`, `environment/v2`. Go-типы переименовать:
  `SecretV1` → `SecretFile`, `EnvironmentV1` → `EnvironmentFile`,
  `ParseSecretV1` → `ParseSecretFile`, `ParseEnvironmentV1` →
  `ParseEnvironmentFile`, `MarshalSecretStable`/`MarshalEnvironmentStable`
  без переименования. `secret/v1`, `environment/v1` — только legacy-разбор
  (§4.14).
- `SecretBody`: удалить `History`; добавить `Versions []VersionHeader`
  (старые первыми, head последний). `HistoryLimit` удалить;
  `VersionWindow = 50`.
- ```go
  type VersionHeader struct {
      ID              string   `yaml:"id"               json:"-"`
      Ref             string   `yaml:"ref"              json:"ref"`     // "dir:name"
      Parent          string   `yaml:"parent,omitempty" json:"parent"`  // "" у genesis
      Author          string   `yaml:"author"           json:"author"`  // SHA256:…
      Recipients      []string `yaml:"recipients"       json:"recipients"` // fingerprints, отсортированы
      PlaintextSHA256 string   `yaml:"plaintext_sha256" json:"plaintext_sha256"`
      PayloadSHA256   string   `yaml:"payload_sha256"   json:"payload_sha256"`
      Created         string   `yaml:"created"          json:"created"` // RFC3339, UTC, секунды
      Signature       string   `yaml:"signature"        json:"-"`
  }
  ```
  Канонический вид = `json.Marshal` структуры (порядок полей — порядок
  объявления; `Parent` всегда присутствует, у genesis пустая строка);
  `ID = sha256hex(canon)`; та же `canon` — сообщение подписи. Golden-тест
  фиксирует байты `canon` для образцового заголовка (в том числе с `<>&` в
  `created`/`ref` не бывает, но тест на экранирование — есть): любая правка
  структуры инвалидирует тест, а не id в проде.
- Компилированный env:
  ```go
  type EnvironmentBody struct {
      Name    string            `yaml:"name"`
      Secrets []SecretFile      `yaml:"secrets"` // у каждого versions = [head]
      Version EnvironmentHeader `yaml:"version"`
  }
  type EnvironmentHeader struct {
      ID        string       `yaml:"id"        json:"-"`
      Env       string       `yaml:"env"       json:"env"`
      Secrets   []EnvSecret  `yaml:"secrets"   json:"secrets"` // {Ref, ID}, в порядке cage.yaml
      Author    string       `yaml:"author"    json:"author"`
      Created   string       `yaml:"created"   json:"created"`
      Signature string       `yaml:"signature" json:"-"`
  }
  ```
  Канон и `id` — так же; namespace `cage-environment`.
- `MarshalSecretStable`: `versions` после `recipients`; `signature` —
  литерал (`|`), `payload` как сейчас. `MarshalEnvironmentStable`: у
  вложенных секретов `versions` обрезается до head; затем `version`.
- Fingerprint: `ssh.FingerprintSHA256` (формат `SHA256:…`, без `=`), общий
  хелпер `FingerprintOfKeyLine(line string) (string, error)` и
  `FingerprintsOfKeyLines([]string) ([]string, error)` (отсортированы).
  `KeyLineComment(line string) string` — комментарий для вывода (помечается
  как непроверенный).

### 4.3 `libcage/chain.go` — проверка цепочки (новый файл)

- `verifySecretFile(s *SecretFile, expectRef string) (*chain, error)`:
  - `versions` непусто; `id` каждого пересчитан; `versions[i].Parent ==
    versions[i-1].ID` для `i ≥ 1` (линейность); `versions[0]` — genesis
    (`parent` пуст) либо checkpoint (родитель вне окна); `len ≤ VersionWindow`;
  - у каждого заголовка `ref == expectRef` (если `expectRef` непуст) и
    name-часть `ref` == `secret.name`;
  - подпись верна, ключ подписи имеет fingerprint `author`;
  - `author ∈ recipients(parent)` для `i ≥ 1`; genesis: `author ∈
    recipients(self)`; checkpoint — авторство не проверяется;
  - head: `payload_sha256 == sha256(DecodePayload(payload))`,
    `plaintext_sha256` совпадает с верхним, `FingerprintsOfKeyLines(
    secret.recipients) == head.recipients`; `created` парсится.
- `chain`: `Head() *VersionHeader`, `Has(id string) bool`, `Index(id) int`,
  `After(id string) []VersionHeader` (заголовки строго после `id`),
  `Checkpoint() bool` (у `versions[0]` есть родитель).
- `relate(store, base *chain) relation`: `Equal` (одинаковый head),
  `Descendant` (`store.Has(base.head.id)`), `Ancestor`
  (`base.Has(store.head.id)`), `Fork` (есть общий `id`, но ни то ни другое),
  `Unrelated` (общего `id` нет). `commonID(store, base) (string, bool)` —
  самый поздний общий `id`.
- `prune(headers []VersionHeader) []VersionHeader` — последние
  `VersionWindow`; вызывается перед записью в `encrypt`.
- `verifyEnvironmentFile(e *EnvironmentFile, expectEnv string) error`:
  `name == expectEnv` (если задан), заголовок `id`/подпись/`author`, список
  `secrets` заголовка совпадает по порядку с вложенными (`ref` и `id`
  head'а), каждый вложенный секрет проходит `verifySecretFile(s, ref)` как
  окно из одного checkpoint-заголовка.
- Ошибки: `*SecurityError{Kind: Integrity, …}` с `ref`/env и причиной (без
  значений).

### 4.4 `libcage/security.go` — типизированная ошибка, код 3

- `type SecurityError struct{Kind SecurityKind; Msg string}`;
  `SecurityKind ∈ {GrantRequired, Integrity}`; `Error()`.
- `main.go: exitErr`: `errors.As(err, &*SecurityError)` → `os.Exit(3)`;
  сообщение выводится как сейчас (`error: …`). Константа `ExitSecurity = 3`;
  таблица кодов в `usage.go`: 0 — ок, 1 — ошибка, 2 — использование,
  3 — безопасность (ничего не записано). `cmd_run.go` пробрасывает код
  дочернего процесса — не трогать.
- `DecryptAll` собирает проблемы по секретам, как сейчас; если среди них
  есть `SecurityError`, итоговая ошибка — `SecurityError{Integrity}` с
  общим списком.

### 4.5 `libcage/identities.go` — подписывающая identity

- `SSHIdentity.Signer ssh.Signer` (из `ssh.ParsePrivateKey`; `nil`, если
  ключ недоступен для подписи: passphrase, неподдерживаемый тип).
  `Fingerprint` заполняется из `Signer.PublicKey()`, когда `Signer != nil`
  (сейчас — только из `.pub`).
- `Identities.SignerFor(fingerprints []string) (SSHIdentity, bool)` —
  первая identity с `Signer != nil`, чей fingerprint ∈ множеству.
- `whoami` показывает, какие identity могут подписывать (`sign: yes/no
  (passphrase)`).

### 4.6 `libcage/local.go` + `sync.go` + `decrypt.go` — база, `.fork`, состояние

- `version`: `SHA`, `File *SecretFile`, `Raw`, `Chain *chain` (вместо
  `History`); для legacy-файла `Chain == nil`. `parseVersion(raw, path,
  expectRef)` вызывает `verifySecretFile`; ошибка целостности — наверх.
  `readStoreVersion`/`readBase` передают `ref`.
- База старого формата → `readBase` возвращает `nil` и пишет `Info:
  discarding pre-signature base`.
- **`.fork`** (`<base>.fork`): raw базы на момент первого неразрешённого
  форка. Пишется `decrypt`'ом, когда `relate(S, B) ∈ {Ancestor, Fork}` и
  файла ещё нет (старейший сохраняется). Удаляется только успешной фазой 2
  `encrypt` для этого секрета (§4.7). `removeBase` удаляет и его. `.prev`
  остаётся как сейчас — предок для 3-way merge plaintext, не для
  безопасности.
- `syncState`: отношения S/B — через `relate`, не через SHA:
  - `in.S.SHA == in.B.SHA` (Modified) → `relate == Equal`;
  - `Outdated` → `L == B.SHA && relate == Descendant`;
  - `Older` → `relate == Ancestor`;
  - `relate == Unrelated` → `SecurityError{Integrity, "<ref>: store history
    was replaced (no version in common with the accepted history)"}`;
  - legacy S (`Chain == nil`): состояние по SHA как сейчас, `in.Legacy =
    true`.
  Сравнения L с S/B по SHA остаются.
- `decryptOne`: до слияния при `Ancestor`/`Fork` — записать `.fork`.
  Затем при `Fork`: `foreign = ∃ h ∈ S.Chain.After(commonID): h.Author ∉
  fp(B.head.recipients)`; если `foreign` → путь `.store`-sidecar (как у
  бинарных) с текстом `conflict: store branch is signed by a key your base
  does not list as recipient (SHA256:… "<comment>") — verify with the owner;
  store version is in <name>.store — cage resolve <ref> -local|-store`;
  иначе — `merge3` как сейчас. Legacy S → `Warn: unsigned legacy store
  file; the owner must republish (cage encrypt)`, дальше как сейчас.
- `commonAncestor` (plaintext для `merge3`): кандидаты `B`, `.prev` — берётся
  тот, чей `head.id` есть в `S.Chain` (вместо `has(SHA)`).
- `resolve`: без изменений (`.fork` не трогает).

### 4.7 `libcage/encrypt.go` — `-grant`, подпись, warn

- Сигнатура: `EncryptAll(opts EncryptOptions)`; `EncryptOptions{Grants
  []string /* fingerprints */; Only []SecretRef /* пусто = все */}`.
  Edit-команды (`finish` в `cmd_edit.go`) передают `Only` = затронутые
  секреты; компилируются только env, ссылающиеся на них; `cage encrypt` —
  всё.
- Фаза 1 (проверка, ничего не пишется) дополняется для каждого секрета:
  - `publish = S == nil || S.Legacy || L != S.SHA || fp(new) != head.
    recipients`; `pending = publish || .fork существует`;
  - если `pending`: исходный список
    - `S == nil || S.Legacy` (genesis): объединение `fp(B.head.recipients)`
      по всем базам `baseRefs()` с `Chain != nil`;
    - иначе `fp(S.head.recipients)`, при `.fork` — `∩ fp(fork.head.
      recipients)`;
  - `added = fp(new) − baseline`, `removed = baseline − fp(new)`;
  - `added ∖ Grants` → пункт отказа (ключ → секрет, путь `env → группа`);
  - подписант: `Ids.SignerFor(head.recipients)` (genesis:
    `SignerFor(fp(new))`); нет → отказ «no identity may sign <ref>: the
    signer must already be a recipient (candidates: …)» (код 1);
  - `Grants`, не встреченные ни в одном `added`, → ошибка «grant not
    needed: SHA256:…» (код 1).
- Отказ (код 3), формат:
  ```
  encrypt refused: new recipients need an explicit grant (nothing written)
    SHA256:abc…  "mallory@laptop" (comment from the key line, unverified)
      ops:db.env   via env ops → group devops
      ops:api.env  via env ops → group devops
    SHA256:def…  "ci@build"
      ops:api.env  via env ci
  Verify each key with its owner over a separate channel. To proceed exactly as listed:
    cage encrypt -grant SHA256:abc… -grant SHA256:def…
  ```
  Путь `env → группа` даёт `ResolveRecipientPaths(cfg, refs) map[fp][]string`
  (вариант `ResolveRecipientRefs`, возвращающий путь).
- Warn на удаление (не блокирует): `WARN recipient removed secret=ops:db.env
  key=SHA256:… comment="…" — the holder still knows the current value;
  rotate it when that matters`.
- Фаза 2 по секрету:
  - `!pending` → `setBase`, как сейчас;
  - `pending && !publish` (только `.fork`, гранты выданы или не нужны) →
    удалить `.fork`, `setBase`;
  - `publish`: заголовок (`ref`, `parent = S.head.id` или пусто, `author`,
    `recipients = fp(new)`, хэши, `created = now UTC`), `id`, подпись,
    `versions = prune(append(S.versions, h))`, запись, `setBase`, удалить
    `.fork`.
- `compileEnv`: вложенные секреты с `versions = [head]`; заголовок env
  (`env`, `secrets` в порядке `cage.yaml`, `author` = первая identity с
  `Signer`, `created`), подпись. Если существующий env-файл верифицируется и
  его `secrets` (ref+id) совпадают — не перезаписывать (иначе каждый
  `encrypt` менял бы подпись и `created`).

### 4.8 Команды

- `cmd_encrypt.go`: флаг `-grant` (повторяемый, fingerprint) →
  `EncryptOptions.Grants`.
- `cmd_edit.go` (`finish`): `EncryptAll(EncryptOptions{Only: refs})`;
  `SecurityError{GrantRequired}` дополняется строкой «the plaintext is
  already changed locally; `cage encrypt -grant …` publishes it together
  with the grants».
- `cmd_verify.go` (новый): `cage verify [-signers file]`:
  - обходит `.cage/store/files/**` → `verifySecretFile(s, ref)`;
    `envs/**` → `verifyEnvironmentFile(e, env)` и `env.version.secrets[i].id
    == store head id` (иначе `Integrity: compiled env <env> does not match
    the store (run cage encrypt)`);
  - при наличии базы — `relate != Unrelated`;
  - `-signers` — head каждого секрета (в store и внутри env) и `author`
    каждого env подписаны ключом из файла;
  - вывод: по файлу `ok  ops:db.env  v=<id[:12]> by SHA256:…  <created>`;
    любая ошибка → список и код 3. Identity не требуется.
- `cmd_credentials.go` / `libcage/credentials.go`:
  - `CredentialsManifest.Signers string` (обязателен, `isCleanAbs`);
    `CredentialSource{Path, Prefix, Secret, Env}` — ровно одно из
    `Secret` (`dir:name`, `ParseSecretRef`) / `Env` (имя); `Validate`
    проверяет;
  - `ComposeCredentials`: после чтения файла — `ReadKind` должен
    соответствовать полю (`secret` ↔ `secret/v2`, `env` ↔
    `environment/v2`), `verifySecretFile(s, Secret)` /
    `verifyEnvironmentFile(e, Env)`, все авторы (head'ы и env) ∈ `signers`;
    иначе `SecurityError{Integrity}` (код 3 preparer'а в journal).
- `run -raw`, `dump` по путям, `decrypt -raw`: общий `loadCageFile(path)
  ([]SecretFile, error)`: если путь лежит под `<root>/.cage/store/`
  (`files/<dir>/<name>.cage`, `envs/<env>.cage`) — ожидаемый `ref`/env
  выводится из пути и проверяется; иначе — проверка без привязки и `Debug:
  no ref binding for <path>` (документируется: вне store привязку
  обеспечивает манифест).
- `dump`/`run`/`inspect` по ref и `@env` внутри корня — через
  `readStoreVersion` (привязка по ref).
- `inspect`/`status`: `version <id[:12]> by SHA256:… <created>`, число
  версий, `legacy (unsigned)`, `fork pending (grants are checked against
  base <id[:12]>)`; `syncHint` — новые состояния.
- `usage.go`: `verify`, `-grant`, `signers`; таблица кодов выхода.

### 4.9 Читатели store — единая точка

Все места из `grep ParseSecretV1|ParseEnvironmentV1|readStoreVersion`
(`dump.go:151,161`, `run_env.go:194,207`, `decrypt_raw.go:44,55`,
`inspect.go:269`, `edit.go:58`, `read_secret.go:13`, `sync.go:52`,
`encrypt.go:157`) переводятся на `readStoreVersion`/`loadCageFile`, которые
проверяют цепочку и привязку. Прямые вызовы `ParseSecretFile`/
`ParseEnvironmentFile` остаются только внутри них и в `chain.go`.

### 4.10 Nix и инфраструктура

- `nix/module.nix`: опция `cage.signersFile` (string, абсолютный runtime-путь
  вне Nix store, обязательна при `enable`); в манифест — `signers`.
  `sourceType`: только submodule (coercion от голого пути убрать), опции
  `secret` (`strMatching "[^:]+:[^:]+"`) и `env`, assertion «ровно одно».
- `nix/tests/fixtures.sh`: `encrypt` → `encrypt -grant …` (fingerprints
  через `ssh-keygen -lf`); генерировать `signers`; негативные фикстуры:
  подменённый payload, подпись не из `signers`, секрет-файл, положенный на
  чужой путь (ошибка привязки), env другого имени.
- VM-тест (`nix/tests/credentials.nix`): новые случаи — отказ на поддельный
  файл, на чужого подписанта, на пересаженный файл; код 3 preparer'а в
  journal.
- `Makefile`/CI: без изменений, кроме прогонки новых тестов.

### 4.11 Документация

- `README.md`: раздел **Trust model** (таблица §3.2, шесть правил из §5),
  обновлённый **Working together** (`-grant`, warn о ротации, `.store`
  при чужом форке, `verify`, код 3), миграция.
- `skill.md`: правило для агента (код 3 → не повторять, не добавлять
  флаги, показать оператору весь список, ждать); `-grant` синтаксис;
  `verify` в чек-листах; смысл warn об удалении; окно версий и что делать
  копии, отставшей больше чем на окно (явный сброс базы — только по решению
  оператора); конфликт «store branch is signed by a key your base does not
  list» — тоже решение оператора.
- `skill_infra.md`: `signers` и `secret`/`env` у источников в манифесте и
  модуле, доставка как identity; отзыв = правка `cage.yaml` **и** `signers`;
  CI: `verify -signers` либо ревью; runtime-источники: привязка — через
  манифест; откат на сервере — не утечка.

### 4.12 Тесты (Go)

- `libssh/sshsig_test.go` — см. 4.1.
- `libcage/formats_test.go`: golden-канон заголовков секрета и env;
  round-trip marshal/parse; legacy kind → `Chain == nil`.
- `libcage/chain_test.go`: валидная цепочка; подделанная подпись; автор не
  получатель родителя; `payload` подменён; fingerprints не совпадают с
  `recipients`; `ref` не совпадает с путём; нелинейный `parent`;
  `relate`: Equal/Descendant/Ancestor/Fork/Unrelated; обрезка: окно ровно K
  после K+5 версий, checkpoint принят копией, у которой точка отреза есть в
  базе; копия старше окна → Unrelated; env: подпись, порядок `secrets`,
  несовпадение с head store, чужое имя.
- `libcage/encrypt_test.go`: grant required (ключи, секреты, пути, текст
  команды); grant принят; лишний grant; genesis на свежем клоне требует
  всех; genesis при наличии баз с этими ключами — без гранта; `.fork`:
  форк отозванного → пересечение → grant; откат к версии до отзыва → то же;
  `.fork` без изменений → удаляется после грантов; warn при удалении; нет
  подписывающей identity; `Only` компилирует только нужные env; env не
  перезаписывается при неизменных head'ах.
- `sync_test.go`: состояния через `relate`; чужой форк → `.store`-конфликт;
  благоприятный форк → `merge3`; Unrelated → код 3; `resolve` не трогает
  `.fork`.
- `credentials_test.go`: `signers` обязателен; `secret`/`env` ровно одно;
  чужой подписант → код 3; пересаженный файл → код 3; env с автором не из
  `signers` → код 3.
- `llm_test.go`: адаптация к формату.
- `main`: таблица «ошибка → код выхода» (1 / 2 / 3).

### 4.13 Порядок работ

1. `sshsig` + тесты.
2. Формат (`v2`, переименования, заголовки, канон, golden) + `chain.go` +
   `SecurityError` + тесты.
3. `identities` (`Signer`, `SignerFor`).
4. `local/sync/decrypt`: `relate`, `.fork`, чужой форк → `.store`;
   `sync_test`.
5. `encrypt` (`-grant`, `Only`, подпись, warn, подписанный env) +
   `cmd_encrypt`/`cmd_edit`; тесты.
6. Единая точка чтения (`run`, `dump`, `inspect`, `raw`, `loadCageFile`).
7. `verify`, `credentials` (`signers`, `secret`/`env`), Nix-модуль,
   фикстуры, VM-тест.
8. README, skill, skill_infra, usage.
9. Прогон: `go test ./...`, `nix flake check`.

### 4.14 Миграция (разовая)

Все обновляют cage. Legacy (`*/v1`) читают только `decrypt` (с Warn) и
`encrypt` (как genesis, с гарантией грантов); остальные команды отказывают
с текстом «unsigned legacy file; the owner must republish». Админ: `cage
decrypt` (база старого формата отбрасывается, plaintext обновляется),
`cage encrypt -grant …` (команда в отказе печатает ключи готовыми; новых
секретов это касается только на свежем клоне). Остальные: `cage decrypt`.
Серверы: доставить `signers`, задать `cage.signersFile` и `secret`/`env` у
источников, перевыкатить. Legacy-разбор удаляется следующим релизом
(отдельная задача: убрать ветку `v1` в `ParseSecretFile`/
`ParseEnvironmentFile`, `Legacy` в `syncInfo`).

---

## 5. Правила, которые объясняет README

1. Версия подписана автором; автор — получатель предыдущей версии (у
   первой — самого себя).
2. Копия принимает store, если цепочка верна и имеет общую версию с её
   базой; иначе код 3.
3. Новый ключ — которого не было у предыдущей версии (у нового секрета —
   ни у одного секрета, принятого этой копией). Ему нужен `-grant`, иначе
   код 3 и ничего не записано.
4. Форк, подписанный не-получателем вашей базы, — конфликт, не слияние.
5. Сервер принимает только подписи ключей из `signers` и только файл на
   своём месте (`secret`/`env` в манифесте).
6. Журнал — последние K версий; отставший больше чем на K начинает заново
   явно.
