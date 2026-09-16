# Validation and design guardrails

Этот файл описывает только актуальные обязательные проверки. Исторические номера сборок, хеши промежуточных EXE, разовые пути и старые test counts сюда не добавляются.

## Release gate

Перед release candidate обязательно:

- `dotnet test tests/XeonV3Control.Tests/XeonV3Control.Tests.csproj -c Release` на Windows x64 с SDK из `global.json`;
- `scripts/Build-Release.ps1` должен завершиться успешно и оставить в `publish` ровно один `XeonV3Control2.exe`;
- `scripts/Test-UI.ps1 -Image <known-valid-image>` должен пройти для всех локализаций из embedded resources;
- страница **Информация о BIOS** должна всегда содержать карточки `BIOS` и `Системная плата`; независимо от источника (файл, полный/частичный SPI dump, BIOS-region dump, модифицированный образ) эти карточки используют только `BiosImage.FirmwareIdentity`, извлечённый из байтов текущего firmware image; Windows SMBIOS/registry не являются fallback или вторым источником истины; board identity допускается только из подтверждённого data-driven BIOS-ID mapping; отсутствующие в образе значения показываются как недоступные;
- вручную проверить запуск, picker, Drag & Drop, выбор/копирование текста, runtime-переключение темы/языка, повторный запуск экземпляра и создание исправленного Secure Boot-образа;
- при аппаратном чтении проверить два независимых чтения с одинаковыми scope/region metadata и SHA-256; для `FullSpi` сверить размер с Intel Descriptor component density, для `PartialSpi` проверить явное перечисление недоступных регионов, для `BiosRegion` — явный fallback; после завершения не должно оставаться transient kernel service/driver;
- запись и стирание flash в текущем продукте отсутствуют; добавлять их можно только отдельным этапом с отдельным security/recovery review.

Статический анализ и XML/JSON/XAML parsing не заменяют Windows build/runtime tests.

## Secure Boot contract

Для распознанной AMI/X99-разметки единая операция **Исправить Secure Boot** создаёт **новый временный образ**, не изменяя исходник и работающую систему:

- удалить обнаруженный известный AMI `DO NOT TRUST` test PK;
- если после его удаления PK-хранилище пусто, создать и поместить в него новый сильный самоподписанный Platform Key; закрытый ключ после создания публичного сертификата не сохранять;
- сохранить уже существующий сильный нетестовый Platform Key;
- удалить известные Microsoft 2011 и распознанные test keys из KEK/db;
- добавить недостающий Microsoft 2023 KEK и три Microsoft 2023 db-сертификата;
- сохранить остальные OEM/неизвестные сертификаты и не затрагивать несвязанные FFS-файлы;
- не перемещать `FFS_ATTRIB_FIXED` и соблюдать PI data-alignment;
- после каждой стадии повторно разобрать образ;
- финально требовать корректную структуру, как минимум один сильный нетестовый Platform Key в каждом управляемом PK-хранилище, полный Microsoft 2023 комплект и отсутствие распознанных Microsoft 2011/test keys в управляемых Secure Boot-хранилищах;
- никогда не считать структурную проверку доказательством пригодности образа к прошивке.

Pinned DER/SHA-256 identities хранятся в certificate resources, а identity драйвера — только в `third_party/ThrottleStop/integrity.json`.

## UEFI driver inspection contract

- учитывать только активные `EFI_FILE_DATA_VALID` DXE/MM FFS-типы в распознанных стандартных PI firmware volumes;
- FFS header/state/checksum и границы должны пройти строгий parser до анализа содержимого;
- рекурсивно разбирать PE32/TE и поддерживаемые encapsulation sections с ограничениями depth/count/expanded bytes; PI EFI standard compression и Tiano custom compression декодировать внутри Core полностью managed C# без native interop;
- известную уязвимость подтверждать только точным GUID + SHA-256 из embedded data catalog; каталог должен оставаться data-driven, а не набором условий в коде;
- W+X executable section — `ReviewRecommended`; повреждённый executable, ошибка декодирования поддерживаемого compression, unsupported guided processing или неполный section stream — `Unknown`;
- generic add/replace/remove остаётся ограничен `UefiDriverMutationPlanner`: он валидирует намерение и feasibility и не предоставляет универсальный write API;
- `UefiDriverUpdatePlanner` адресует точный экземпляр драйвера (GUID + FV/FFS offset + SHA-256), повторно инспектирует replacement FFS и блокирует уверенные downgrade/architecture/subsystem/security regressions; изменение структуры секций или dependency expressions допускается к дальнейшему рассмотрению только X99 policy layer;
- исполняемый путь существует только через `X99UefiDriverUpdatePlanner` + `X99UefiDriverImageUpdater`: exact source FFS SHA-256 должен иметь catalog-pinned exact candidate SHA-256 и пройти повторную source/candidate/physical reauthorization непосредственно перед записью; blind same-GUID/latest-version replacement запрещён;
- UI обязан явно отделять **полный inventory найденных UEFI-драйверов** от меньшего списка компонентов с проверенной update/restriction policy; для `Ready && CanApply` показывается индивидуальная кнопка `Обновить`, для `UpToDate` — неактивное `Актуально`, неподтверждённые переходы не становятся кнопкой изменения; update начинается без дополнительного `ContentDialog`, bulk update отсутствует;
- theme-sensitive driver colors должны приходить только из XAML `ThemeResource`; generic add/remove и произвольная replacement-кнопка в UI запрещены.

## TurboBoost Unlock / CPU Patch contract

- детектор работает полностью внутри Core; запуск MMTool, UEFITool, Python-detector или другого стороннего процесса запрещён;
- verified Unlock требует точной известной идентичности либо калиброванного family fingerprint с совпадающей PE-структурой, требуемым прямым MSR-поведением и порогами профиля; близкий профиль или сильная общая MSR-семантика дают только `Possible`; точный curated-clean executable имеет приоритет как veto;
- политика очистки Unlock data-driven: `retainedFamilies` сейчас пуст; `ser8989-turbohack` является `Foreign` наравне с другими известными семействами; только verified-модуль ровно одного известного и не-retained семейства получает `Foreign`, а near/generic/ambiguous-кандидаты остаются `Unclassified` и не авторизуют очистку;
- прямой `RemoveInjectedFfs` не требует clean baseline: source-analysis должен быть полным, модуль — verified `Foreign` ровно одного известного не-retained семейства, а finding — локализован в одном точном активном FFS; GUID, имя, отдельная строка, near/generic semantics, ambiguous-family и `Unclassified` не авторизуют изменение;
- перед записью executor обязан повторно прочитать текущий source, проверить source SHA-256, заново выполнить TurboBoost/UEFI анализ и заново подтвердить exact Foreign target; caller-supplied `Ready` plan сам по себе не является доверием;
- exact low-level preflight для `RemoveInjectedFfs` не ограничивается DXE/MM типами и допускает, например, verified Foreign PEIM, но только после независимой Foreign-authorisation и exact GUID/FV/FFS offset/size/type/SHA-256; требуется активный `DataValid` FFS, корректно разобранный стандартный FV/FFS, поддерживаемая erase polarity и отсутствие `FFS_ATTRIB_FIXED`; публичный `UefiDriverMutationPlanner` остаётся driver-only;
- физическое удаление меняет только PI FFS state-byte `DataValid → Deleted`; output должен отличаться от source ровно этим байтом, сохранять FFS/FV layout, все unrelated TurboBoost-модули и все microcode, пройти полный повторный managed analysis и не менять наличие CPU Patch `6F 06F2`;
- TurboBoost UI показывает индивидуальную кнопку только для `Ready/RemoveInjectedFfs`; после нажатия удаление начинается сразу, без дополнительного `ContentDialog`; clean-BIOS picker и bulk «удалить все» для прямого удаления запрещены;
- mutation-действия Secure Boot / CPU Patch / Foreign Unlock не должны блокировать UI-thread: `RunOperation` сначала отдаёт dispatcher turn для отображения busy-state, а тяжёлый updater/re-analysis выполняется через `Task.Run`;
- кнопки удаления CPU Patch и individual Foreign Unlock запускают уже preflight-gated операцию сразу, без второго `ContentDialog`; fail-closed проверки executor сохраняются обязательными;
- `PlanAgainstBaseline` остаётся только backend-инструментом для исследования будущего `RestoreBaselineFfs`: он проверяет exact source/baseline identity/layout/topology и может доказать modified/replaced stock FFS или дополнительный FFS, но baseline никогда не является execution dependency для прямого удаления; modified/replaced stock FFS остаётся в `RequiresBaselineByteAuthorization` до отдельного доказательства byte compatibility;
- baseline никогда не должен восстанавливать удалённый Foreign Unlock или состояние CPU Patch `6F 06F2`; состояние CPU Patch является независимым источником истины;
- Intel microcode учитывается только после проверки header version/loader revision/размеров/границ и 32-bit additive checksum; целевой CPU Patch для TurboBoost Unlock определяется строго как Haswell-E/EP `platform flags 0x6F + processor signature 0x000306F2` (`6F 06F2`), а не как произвольный microcode;
- удаление CPU Patch разрешается только для `CpuPatchRemovalPlan.Ready`, привязанного к SHA-256 исходного образа, SHA-256 microcode и точному FFS/FV расположению; updater обязан повторно проверить source identity, активный RAW FFS, непрерывную последовательность microcode, поддерживаемый tail и точное соответствие Intel FIT type-1 entries;
- managed updater не меняет размер/позицию FFS или FV: оставшиеся microcode копируются без изменения байтов, свободное место заполняется erase-byte тома, `MPDT` footer сохраняется, FFS checksum пересчитывается, Intel FIT канонически уплотняется: удаляется только type-1 entry целевого `6F 06F2`, адреса оставшихся microcode обновляются, все прочие используемые FIT entries сохраняются побайтно и в исходном относительном порядке, затем все использованные entries размещаются непрерывно после header, хвост становится unused (`0xFF`), а FIT header checksum пересчитывается только если его `C_V` установлен;
- файловая операция использует `CreateNew`, временный partial + SHA-256 verification и TOCTOU-защиту по SHA-256 исходного образа; исходный BIOS никогда не перезаписывается; после записи новый файл обязан пройти `BiosImageLoader.LoadValidatedAsync`, а удалённый microcode SHA-256 не должен присутствовать в повторном анализе;
- reference `8DPV11.bin` должен находить единственный валидный `6F 06F2` patch revision `0x3D`, date `2018-04-20`, size `0x8400`, SHA-256 `711E1F2274183AD14C0597759CF4BADD27AAFF46734B842BAB2850DDF00A640D`, не объявляя сам stock-образ TurboBoost Unlock; после удаления статус CPU Patch должен стать «удалён/отсутствует» и на странице информации, и на странице TurboBoost Unlock; эталонный результат managed-repack для этого fixture имеет SHA-256 `509B6DA151449BEACD6508430BF6B86638E7DEFF8C2034A94677129460CFD137`;
- пара `8DPV11.bin` / `TurboUnlock/ForeignCleanup/8DPV11_nalex_upt.bin` является regression для Nalex/UPT: modified image SHA-256 `5342AD0738155EE32FF546E62335FCFF6311A98329553A4AA7C927A959C2E293`, exact Foreign FFS GUID `9C81BC4D-A8F5-4D3D-BB75-5AA2E934A034`, offset `0x8C9AE8`, size `2347`, FFS SHA-256 `9068ED21C0BE8524D5B554307D49EA4D44F647CC700FF0D706F477D8BF784D5A`; direct cleanup меняет только state byte `0x8C9AFF: F8 -> E8`, не пытается восстановить весь stock BIOS и не меняет CPU Patch/microcodes;
- раздел TPM на этом этапе является пустым placeholder и не должен имитировать результаты проверки.

## Windows 11 / Fluent design guardrails

Используются принципы Microsoft Windows 11 Design principles:

- **Effortless** — безопасный основной сценарий без лишних подтверждений; запись flash не входит в текущий продукт и потребует отдельного контракта подтверждения и восстановления, если когда-либо будет добавлена.
- **Calm** — цвет только как семантика состояния/риска; обычный контент нейтральный.
- **Personal** — System/Light/Dark и язык меняются во время работы и сохраняются без расхождения persisted/UI state.
- **Familiar** — стандартные WinUI controls, `NavigationView`, `InfoBar`, системные glyphs и стандартный settings item вместо самодельных аналогов.
- **Complete + coherent** — единые design tokens, одинаковая иерархия page heading → subtitle → cards → actions.
- **Adaptive** — `NavigationView` Expanded/Compact/Minimal, рабочая колонка центрируется внутри фактического content viewport, карточки не зависят от фиксированной ширины, узкие/средние/широкие состояния входят в smoke regression.
- **Accessibility** — состояние не передаётся одним цветом: текст + severity/icon; focus/keyboard/selection должны оставаться штатными WinUI.

Практические последствия:

- Warning/Error/Success оформляются стандартной severity-семантикой WinUI;
- на отдельной странице не повторять тот же заголовок внутри первой карточки;
- primary action один и визуально отличается от secondary actions;
- технические списки сертификатов используют переносимые вертикальные карточки, а не фиксированные узкие колонки;
- пользовательские уведомления закрываемые; на странице Secure Boot используется один page-level `InfoBar`, включая результат/ошибку/отмену операции обновления, вместо уведомлений в разных частях окна;
- выделение/копирование текста — обязательный STA/runtime regression.

Reference: Microsoft Learn — `windows/apps/design/design-principles`.

## Security/lifecycle guardrails

- приложение x64/unpackaged/single-file и требует elevation только потому, что hardware read path использует kernel driver;
- анализ обычного файла не должен загружать driver;
- transient application data размещаются в защищённом `CommonApplicationData` storage с закрытым DACL и no-follow checks;
- crash report сначала пишется рядом с EXE, затем — в защищённый fallback;
- single-instance registration происходит до XAML startup;
- UI process entry thread обязан быть STA; `async Main` запрещён;
- cancellation не может оставлять transient service; cleanup уже загруженного driver неотменяемый;
- secondary cleanup failure не подменяет исходную ошибку;
- NuGet audit включён, package versions централизованы в `Directory.Packages.props`.


## X99 UEFI driver update / firmware-volume rebuild

Automatic UEFI-driver mutation is narrower than generic inspection/planning. `UefiDriverUpdatePlanner` still has no write API. Execution is exposed only through `X99UefiDriverImageUpdater` after `X99UefiDriverUpdatePlanner` authorizes an exact source-FFS SHA-256 to exact embedded candidate SHA-256 transition from `Firmware/x99-driver-updates.json`. Never authorize by GUID, UI name, version string, or “newest same-GUID” alone.

Current reviewed transitions from the supplied corpus are Intel RST `13.1.0.2126 -> 14.8.0.2377`, Intel RST `13.2.0.2134 -> 14.8.0.2377`, and Intel RSTe `4.6.0.1018 -> 5.5.5.1005`. Intel LAN/Atheros/Killer LAN require controller/hardware authorization; AMI NVMe/NvmeInt13/NvmeDynamicSetup require bundle authorization; Realtek UNDI, Marvell 9172, ASMedia ASM106x and generic OEM RAID variants have no proven exact upgrade chain in the supplied corpus. GUID `5BBA83E5-F027-4CA7-BFD0-16358CC9E123` is observed as `IccOverClocking` in the supplied corpus/reference image and must never be mislabeled as an Intel GOP target.

Physical planning has five outcomes:

- `InPlace`: target stays at the exact FFS offset and no following file moves; erased tail may be reused when the target is last.
- `GrowIntoAdjacentFreeSpace`: target stays at the exact offset and consumes adjacent PAD/free space; any remaining representable gap is regenerated as a valid PI PAD FFS; the next non-PAD file keeps its offset and bytes.
- `RebuildFirmwareVolume`: FV `Start/End/FirstFileOffset`, filesystem, erase polarity, header bytes and total `FvLength` remain unchanged. The file area from the target onward is regenerated, existing PAD is normalized, ordinary movable DXE/MM/application files may change offsets, and a pure PEIM may move only when `UefiXipPeRebaser` proves and performs the strict XIP relocation described below.
- `RequiresRebase`: a position-sensitive PEI file would have to move but the current strict rebase contract cannot prove it safe. SEC/PEI core, combined PEIM/DXE, TE, compressed/guided/nested PEI, stripped/unsupported relocations, ambiguous RVA mapping or mismatched physical `ImageBase` stay fail-closed.
- `Unsupported`: insufficient space, invalid/transitional FFS, duplicate non-PAD GUID, invalid VTF placement, fixed/unknown file movement, metadata/alignment mismatch or an unrepresentable PAD gap.

The FV rebuilder must never resize an FV, alter bytes before its mutation range or outside the target FV, move a `FFS_ATTRIB_FIXED` file, move the VTF, or silently move an unknown/PEI-sensitive file. VTF, when present, remains the final file ending exactly at the FV end. Candidate GUID/type/attributes/header shape and data alignment are revalidated against the target. All active files must parse as `DataValid`; generated PAD files must independently parse and checksum correctly.

Strict PEIM rebasing is intentionally narrower than generic PE rebasing: it is allowed only for a pure `FFS type 0x06` inside a complete power-of-two Intel SPI image with a validated Descriptor at offset 0 and a BIOS region containing both old and new locations. The PEIM must contain exactly one direct uncompressed PE32/PE32+ section and no TE/compression/guided/disposable wrapper; PE machine must be IA32 or x64; `ImageBase` must equal the current `4 GiB - SPI size + PE payload offset`; section/file alignment must match and every raw section must use XIP `PointerToRawData == VirtualAddress`; relocations must be present, unstripped, uniquely mappable and consist only of `ABSOLUTE` plus `HIGHLOW` (IA32) or `DIR64` (x64). Every non-ABSOLUTE relocation target is range-checked before the delta is applied. The new FFS checksum is recalculated and the rewritten FFS is reparsed as `DataValid`. Any failed invariant yields `RequiresRebase / PeiRebaseNotProvable`, not a best-effort move.

Executor postconditions are fail-closed: re-read/re-analyze exact source SHA before mutation; re-plan the exact transition; verify embedded candidate SHA; reparse the rebuilt FV; require the exact candidate once; preserve unrelated driver semantic identities (offset change allowed only for non-fixed files under `RebuildFirmwareVolume`); preserve TurboBoost modules semantically; preserve all microcodes exactly and preserve `HasXeonE5V3CpuPatch`; preserve image kind/size/regions/FV metadata; write only a new side file and never overwrite an existing destination.

Regression fixtures cover exact RST in-place update, RSTe growth into free FV tail, consumption/regeneration of adjacent PAD, full FV rebuild with a moved ordinary DXE, fail-closed `RequiresRebase` for a PEIM whose relocation cannot be proven, and successful relocation of a synthetic direct IA32 PE32 XIP PEIM with a valid base-relocation block. `tests/8DPV11.bin` already contains exact RST `14.8.0.2377` and must report `UpToDate`.
