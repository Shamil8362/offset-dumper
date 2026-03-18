export const LANGS = { ru:'RU', en:'EN', pt:'PT', tr:'TR' }

const T = {
  tabProcesses:   { ru:'Процессы',      en:'Processes',     pt:'Processos',     tr:'İşlemler'      },
  tabFile:        { ru:'Файл',          en:'File Scan',     pt:'Arquivo',       tr:'Dosya'         },
  tabMemory:      { ru:'Память',        en:'Memory',        pt:'Memória',       tr:'Bellek'        },
  tabChain:       { ru:'Цепь PTR',      en:'PTR Chain',     pt:'Cadeia PTR',    tr:'PTR Zincir'    },
  tabActive:      { ru:'Активные',      en:'Active',        pt:'Ativos',        tr:'Aktif'         },
  tabBackground:  { ru:'Фоновые',       en:'Background',    pt:'Segundo plano', tr:'Arka plan'     },
  opLog:          { ru:'Лог',           en:'Log',           pt:'Log',           tr:'Günlük'        },

  refresh:        { ru:'Обновить',      en:'Refresh',       pt:'Atualizar',     tr:'Yenile'        },
  scan:           { ru:'Сканировать',   en:'Scan',          pt:'Escanear',      tr:'Tara'          },
  attachScan:     { ru:'Подключить и сканировать', en:'Attach & Scan', pt:'Anexar e Escanear', tr:'Bağla ve Tara' },
  resolve:        { ru:'Резолвить',     en:'Resolve',       pt:'Resolver',      tr:'Çöz'           },
  clear:          { ru:'Очистить',      en:'Clear',         pt:'Limpar',        tr:'Temizle'       },
  scanning:       { ru:'Сканирую...',   en:'Scanning...',   pt:'Escaneando...', tr:'Taranıyor...'  },
  autoRefresh:    { ru:'Авто-обновление', en:'Auto-refresh', pt:'Atualização auto', tr:'Otomatik yenile' },
  exportHpp:      { ru:'Экспорт .hpp',  en:'Export .hpp',   pt:'Exportar .hpp', tr:'.hpp Dışa Aktar' },
  outputPath:     { ru:'Путь файла',    en:'Output path',   pt:'Caminho de saída', tr:'Çıkış yolu' },
  cancel:         { ru:'Отмена',        en:'Cancel',        pt:'Cancelar',      tr:'İptal'         },
  export:         { ru:'Сохранить',     en:'Save',          pt:'Salvar',        tr:'Kaydet'        },
  done:           { ru:'Готово',        en:'Done',          pt:'Concluído',     tr:'Tamamlandı'    },

  ctxMemScan:     { ru:'Сканировать память',  en:'Scan Memory',       pt:'Escanear Memória',    tr:'Belleği Tara'    },
  ctxChain:       { ru:'Резолвить цепь PTR',  en:'Resolve PTR Chain', pt:'Resolver Cadeia PTR', tr:'PTR Zincir Çöz'  },
  ctxSelect:      { ru:'Выбрать процесс',     en:'Select Process',    pt:'Selecionar Processo', tr:'İşlem Seç'       },

  filterByName:   { ru:'Фильтр по имени...',  en:'Filter by name...', pt:'Filtrar por nome...', tr:'İsme göre filtrele...' },
  clickRefresh:   { ru:'Нажмите Обновить',    en:'Click Refresh',     pt:'Clique em Atualizar', tr:'Yenile\'ye tıklayın'   },
  clickToAction:  { ru:'Клик — действия',     en:'Click for actions', pt:'Clique para ações',   tr:'Tıklayın'              },
  dblClickMem:    { ru:'Двойной клик — Memory Scan', en:'Double-click to Memory Scan', pt:'Duplo clique para escanear', tr:'Çift tıklama ile bellek tara' },
  noResults:      { ru:'Нет результатов',     en:'No results',        pt:'Sem resultados',      tr:'Sonuç yok'        },
  noProcessSelected: { ru:'Процесс не выбран', en:'No process selected', pt:'Nenhum processo', tr:'İşlem seçilmedi' },

  peFilePath:     { ru:'Путь к PE файлу',    en:'PE File Path',      pt:'Caminho PE',          tr:'PE Dosya Yolu'    },
  aobPattern:     { ru:'AOB Паттерн',         en:'AOB Pattern',       pt:'Padrão AOB',          tr:'AOB Deseni'       },
  optional:       { ru:'необязательно',       en:'optional',          pt:'opcional',            tr:'isteğe bağlı'     },
  processName:    { ru:'Имя процесса',        en:'Process Name',      pt:'Nome do Processo',    tr:'İşlem Adı'        },
  pointerChain:   { ru:'Цепь указателей',     en:'Pointer Chain',     pt:'Cadeia de Ponteiro',  tr:'İşaretçi Zinciri' },
  hexColon:       { ru:'hex через двоеточие', en:'hex, colon-sep',    pt:'hex, separado por :', tr:'hex, iki nokta'   },

  loaded:         { ru:'Загружено',    en:'Loaded',    pt:'Carregado',  tr:'Yüklendi'    },
  attached:       { ru:'Подключено',   en:'Attached',  pt:'Conectado',  tr:'Bağlandı'    },
  resolved:       { ru:'Резолвлено',   en:'Resolved',  pt:'Resolvido',  tr:'Çözüldü'     },
  invalid:        { ru:'Невалидно',    en:'Invalid',   pt:'Inválido',   tr:'Geçersiz'    },
  sections:       { ru:'Секции',       en:'Sections',  pt:'Seções',     tr:'Bölümler'    },
  patternMatches: { ru:'Совпадения',   en:'Matches',   pt:'Correspondências', tr:'Eşleşmeler' },
  hits:           { ru:'совп.',        en:'hits',      pt:'corr.',      tr:'eşl.'        },
  loadedModules:  { ru:'Модули',       en:'Modules',   pt:'Módulos',    tr:'Modüller'    },
  finalAddress:   { ru:'Адрес',        en:'Address',   pt:'Endereço',   tr:'Adres'       },
  module:         { ru:'Модуль',       en:'Module',    pt:'Módulo',     tr:'Modül'       },
  baseOffset:     { ru:'Базовый офф.', en:'Base Offset', pt:'Offset Base', tr:'Temel Offset' },
  chainHistory:   { ru:'История цепей', en:'Chain history', pt:'Histórico', tr:'Zincir geçmişi' },

  colName:      { ru:'Имя',        en:'Name',       pt:'Nome',       tr:'Ad'           },
  colVa:        { ru:'Вирт. адрес', en:'Virt. Addr', pt:'End. Virtual', tr:'Sanal Adres' },
  colSize:      { ru:'Размер',     en:'Size',       pt:'Tamanho',    tr:'Boyut'        },
  colRawOffset: { ru:'Raw Offset', en:'Raw Offset', pt:'Offset Bruto', tr:'Ham Offset'  },
  colRva:       { ru:'RVA',        en:'RVA',        pt:'RVA',        tr:'RVA'          },
  colSection:   { ru:'Секция',     en:'Section',    pt:'Seção',      tr:'Bölüm'        },
  colRipTarget: { ru:'RIP Цель',   en:'RIP Target', pt:'Alvo RIP',   tr:'RIP Hedef'    },
  colAddress:   { ru:'Адрес',      en:'Address',    pt:'Endereço',   tr:'Adres'        },
  colBase:      { ru:'База',       en:'Base',       pt:'Base',       tr:'Taban'        },

  howToUse:    { ru:'Как использовать', en:'How to use',  pt:'Como usar',     tr:'Nasıl kullanılır' },
  chainHelp1:  { ru:'Введи оффсеты через двоеточие (hex).',
                  en:'Enter offsets as hex values separated by colons.',
                  pt:'Insira offsets hex separados por dois pontos.',
                  tr:'Offsetleri iki nokta ile ayrılmış hex olarak girin.' },
  chainHelp2:  { ru:'Первый = базовый оффсет, остальные = цепь.',
                  en:'First = base offset, rest = pointer chain.',
                  pt:'Primeiro = offset base, restante = cadeia.',
                  tr:'İlki = temel offset, geri kalanı = zincir.' },
  chainHelp3:  { ru:'Резолвится как:', en:'Resolves as:', pt:'Resolve como:', tr:'Çözünürlük:' },

  noSections:  { ru:'Нет секций',     en:'No sections', pt:'Sem seções',  tr:'Bölüm yok'   },
  noMatches:   { ru:'Нет совпадений', en:'No matches',  pt:'Sem correspondências', tr:'Eşleşme yok' },
  noModules:   { ru:'Нет модулей',    en:'No modules',  pt:'Sem módulos', tr:'Modül yok'   },
  noActivity:  { ru:'Активности нет', en:'No activity', pt:'Sem atividade', tr:'Etkinlik yok' },

  logListProc:     { ru:'Получаю процессы...', en:'Listing processes...', pt:'Listando processos...', tr:'İşlemler listeleniyor...' },
  logFound:        { ru:'Найдено',    en:'Found',     pt:'Encontrado', tr:'Bulundu'    },
  logActive:       { ru:'активных',   en:'active',    pt:'ativos',     tr:'aktif'      },
  logScanFile:     { ru:'Сканирую файл', en:'Scanning file', pt:'Escaneando arquivo', tr:'Dosya taranıyor' },
  logAttach:       { ru:'Подключаюсь', en:'Attaching', pt:'Conectando', tr:'Bağlanıyor' },
  logResolve:      { ru:'Резолвлю',   en:'Resolving', pt:'Resolvendo', tr:'Çözülüyor'  },
  logDone:         { ru:'Готово',     en:'Done',      pt:'Concluído',  tr:'Tamamlandı' },
  logChainInvalid: { ru:'Цепь невалидна', en:'Chain invalid', pt:'Cadeia inválida', tr:'Zincir geçersiz' },


  // NetVars page
  netvarInfo:      { ru:'Работает только с играми на движке Source (CS:GO, CS2, TF2, L4D2). Подключается к запущенной игре и автоматически дампит все поля и оффсеты.',
                     en:'Works only with Source engine games (CS:GO, CS2, TF2, L4D2). Attaches to the running game and automatically dumps all fields and offsets.',
                     pt:'Funciona apenas com jogos Source engine. Conecta ao jogo em execucao e despeja automaticamente todos os campos e offsets.',
                     tr:'Yalnizca Source engine oyunlarinda calisir. Calisan oyuna baglanir ve tum alanlari otomatik olarak dokumler.' },
  netvarEmptyDesc: { ru:'Запусти игру на движке Source, введи имя процесса и нажми Dump NetVars',
                     en:'Run a Source engine game, enter the process name and click Dump NetVars',
                     pt:'Execute um jogo Source engine, insira o nome do processo e clique em Dump NetVars',
                     tr:'Source engine oyununu baslat, islem adini gir ve Dump NetVars a tikla' },
  netvarStep1:     { ru:'Запусти игру (CS:GO, CS2, TF2 и т.д.) и дождись главного меню',
                     en:'Launch the game (CS:GO, CS2, TF2, etc.) and wait for the main menu',
                     pt:'Inicie o jogo e aguarde o menu principal',
                     tr:'Oyunu baslat ve ana menuyu bekle' },
  netvarStep2:     { ru:'Введи имя процесса — csgo.exe, cs2.exe, hl2.exe',
                     en:'Enter the process name — csgo.exe, cs2.exe, hl2.exe',
                     pt:'Insira o nome do processo — csgo.exe, cs2.exe',
                     tr:'Islem adini gir — csgo.exe, cs2.exe' },
  netvarStep3:     { ru:'Нажми Dump NetVars — программа автоматически найдёт все оффсеты',
                     en:'Click Dump NetVars — the tool will automatically find all offsets',
                     pt:'Clique em Dump NetVars — a ferramenta encontrara todos os offsets',
                     tr:'Dump NetVars a tikla — arac tum offsetleri otomatik bulacak' },
  netvarStep4:     { ru:'Выбери формат и скачай готовый файл с оффсетами',
                     en:'Choose a format and download the ready-made offsets file',
                     pt:'Escolha um formato e baixe o arquivo de offsets',
                     tr:'Format sec ve hazir offsetler dosyasini indir' },
  classes:         { ru:'Классы',     en:'Classes',    pt:'Classes',    tr:'Siniflar'  },
  allClasses:      { ru:'Все классы', en:'All classes', pt:'Todas',     tr:'Hepsi'     },
  // Signatures page
  tabSigs:       { ru:'Сигнатуры',        en:'Signatures',    pt:'Assinaturas',   tr:'İmzalar'        },
  importCfg:     { ru:'Импорт',           en:'Import',        pt:'Importar',      tr:'İçe Aktar'      },
  exportCfg:     { ru:'Экспорт конфига',  en:'Export Config', pt:'Exportar Config', tr:'Config Dışa'  },
  addSig:        { ru:'Добавить',         en:'Add',           pt:'Adicionar',     tr:'Ekle'           },
  noSigs:        { ru:'Нет сигнатур',     en:'No signatures', pt:'Sem assinaturas', tr:'İmza yok'     },
  editSig:       { ru:'Редактировать',    en:'Edit',          pt:'Editar',        tr:'Düzenle'        },
  saveSig:       { ru:'Сохранить',        en:'Save',          pt:'Salvar',        tr:'Kaydet'         },
  sigName:       { ru:'Имя',             en:'Name',          pt:'Nome',          tr:'Ad'             },
  sigModule:     { ru:'Модуль',           en:'Module',        pt:'Módulo',        tr:'Modül'          },
  sigPattern:    { ru:'AOB Паттерн',      en:'AOB Pattern',   pt:'Padrão AOB',    tr:'AOB Deseni'     },
  sigOffset:     { ru:'Offset',           en:'Offset',        pt:'Offset',        tr:'Offset'         },
  sigExtra:      { ru:'Extra',            en:'Extra',         pt:'Extra',         tr:'Ekstra'         },
  sigRelative:   { ru:'Тип',             en:'Type',          pt:'Tipo',          tr:'Tür'            },
  sigOffsetHelp: { ru:'Байт от начала совпадения до 4-байтного смещения',
                   en:'Byte position from match start to the 4-byte displacement',
                   pt:'Posição em bytes do início da correspondência ao deslocamento de 4 bytes',
                   tr:'Eşleşme başından 4 baytlık yerleşime bayt konumu' },
  sigExtraHelp:  { ru:'Константа прибавляемая к финальному адресу (hex или dec)',
                   en:'Constant added to the final address (hex or dec)',
                   pt:'Constante adicionada ao endereço final (hex ou dec)',
                   tr:'Son adrese eklenen sabit (hex veya dec)' },
  sigRelativeHelp: { ru:'RIP-relative: читать 4-байт displacement. Absolute: offset = RVA + offset',
                     en:'RIP-relative: read 4-byte displacement. Absolute: offset = RVA + offset',
                     pt:'RIP-relativo: lê deslocamento de 4 bytes. Absoluto: offset = RVA + offset',
                     tr:'RIP-goreceli: 4 bayt yerlesim okur. Mutlak: offset = RVA + offset' },
  scanTarget:    { ru:'Цель сканирования', en:'Scan Target',  pt:'Alvo da Varredura', tr:'Tarama Hedefi' },
  liveProcess:   { ru:'Живой процесс',    en:'Live Process',  pt:'Processo Ativo', tr:'Canlı İşlem'   },
  staticFile:    { ru:'Статический файл', en:'Static File',   pt:'Arquivo Estático', tr:'Statik Dosya' },
  batchScan:     { ru:'Batch Scan',       en:'Batch Scan',    pt:'Varredura em Lote', tr:'Toplu Tara'  },
  sigsReady:     { ru:'сигнатур с паттернами', en:'sigs with patterns', pt:'assinaturas com padrões', tr:'desen içeren imza' },
  results:       { ru:'Результаты',       en:'Results',       pt:'Resultados',    tr:'Sonuçlar'       },
  found:         { ru:'найдено',          en:'found',         pt:'encontrado',    tr:'bulundu'        },
  copy:          { ru:'Копировать',       en:'Copy',          pt:'Copiar',        tr:'Kopyala'        },
  download:      { ru:'Скачать',          en:'Download',      pt:'Baixar',        tr:'İndir'          },
  logModules:      { ru:'модулей',    en:'modules',   pt:'módulos',    tr:'modüller'   },
}

export function useLang(lang) {
  return (key) => {
    const e = T[key]
    if (!e) return key
    return e[lang] || e['en'] || key
  }
}

// README translations — appended
export const README = {
  ru: {
    title: 'Справка — OffsetDumper',
    sections: [
      {
        heading: 'Что такое оффсет?',
        body: `Оффсет (offset) — это смещение от базового адреса модуля до нужной переменной или функции в памяти процесса.

Например: game.exe загружается по адресу 0x140000000. Переменная health находится по адресу 0x1401A2B00. Оффсет = 0x1A2B00.

Оффсеты бывают двух видов:
• Статические — не меняются между запусками (RVA в PE файле)
• Динамические — меняются каждый запуск из-за ASLR, нужна цепь указателей`
      },
      {
        heading: 'PROC — Процессы',
        body: `Список всех запущенных процессов Windows.

Вкладка "Активные" — процессы с видимым окном (игры, приложения).
Вкладка "Фоновые" — системные службы, демоны.

Горячие клавиши:
• / — фокус на поиск
• Клик — меню действий (Memory Scan, PTR Chain)
• Двойной клик — сразу Memory Scan

Авто-обновление обновляет список каждые 3 секунды без перезагрузки страницы.`
      },
      {
        heading: 'FILE — Статический анализ',
        body: `Анализирует PE файл (.exe / .dll) без его запуска.

Что показывает:
• ImageBase — базовый адрес загрузки
• EntryPoint — точка входа программы
• Секции — .text (код), .data (данные), .rdata (константы) и др.
• AOB совпадения — адреса найденных байт-паттернов

AOB паттерн (Array of Bytes) — последовательность байт в IDA стиле:
48 8B 05 ? ? ? ? 48 89

Знак ? — wildcard, любой байт. Используется чтобы пропустить адреса внутри инструкций которые меняются при каждой компиляции.

Найденный RVA стабилен — работает независимо от ASLR.
RIP Target — адрес на который ссылается инструкция (для MOV RAX, [RIP+offset]).`
      },
      {
        heading: 'MEM — Сканирование памяти',
        body: `Подключается к живому процессу и сканирует его память.

Использует Windows API: OpenProcess → ReadProcessMemory → VirtualQueryEx.

Показывает:
• Загруженные модули (.exe + все .dll) с базовыми адресами
• Совпадения AOB паттерна с абсолютным адресом и RVA

Важно: абсолютный адрес (Address) меняется при каждом перезапуске игры.
RVA = Address − ModuleBase — стабилен, используй его.

Требует запущенного процесса и прав на чтение памяти.`
      },
      {
        heading: 'PTR — Цепь указателей',
        body: `Резолвит многоуровневую цепь указателей для поиска динамических объектов.

Формат: базовый_оффсет:оффсет1:оффсет2:оффсет3
Пример: 0x1A2B00:0x10:0x20:0x5C

Как работает:
1. Берём module_base + 0x1A2B00 → читаем qword → получаем адрес объекта
2. адрес_объекта + 0x10 → читаем qword → следующий указатель
3. + 0x20 → читаем qword
4. + 0x5C → финальный адрес (поле структуры)

Используется когда объект создаётся динамически (new/malloc) и его адрес меняется. Цепь указателей через статический корневой указатель остаётся постоянной.

История — последние 5 резолвленных цепей, кликни чтобы повторить.`
      },
      {
        heading: 'Экспорт .hpp',
        body: `После сканирования появляется кнопка "Экспорт .hpp".

Генерирует C++ заголовочный файл с найденными оффсетами:

namespace Offsets {
    constexpr uintptr_t match_0 = 0x1A2B00; // .text
    constexpr uintptr_t match_1 = 0x1A3C10; // .text
}

Файл можно подключить в свой проект и использовать оффсеты напрямую.`
      },
      {
        heading: 'Статический vs Динамический',
        body: `Статический оффсет (RVA из File/Memory Scan):
✓ Не меняется между запусками
✓ Работает после обновления игры (если структура не изменилась)
✓ Используй в своих инструментах как константу

Динамический адрес (Address из Memory Scan):
✗ Меняется каждый запуск из-за ASLR
✗ Нельзя хардкодить
✓ Полезен для отладки прямо сейчас

AOB паттерн — самый надёжный способ:
✓ Работает даже после обновления игры
✓ Не зависит от адресов — ищет по сигнатуре байт
✓ RIP Target даёт финальный статический оффсет автоматически`
      }
    ]
  },
  en: {
    title: 'Help — OffsetDumper',
    sections: [
      {
        heading: 'What is an offset?',
        body: `An offset is the displacement from a module's base address to a variable or function in process memory.

Example: game.exe loads at 0x140000000. Variable "health" is at 0x1401A2B00. Offset = 0x1A2B00.

Two types of offsets:
• Static — don't change between runs (RVA in the PE file)
• Dynamic — change every run due to ASLR, need a pointer chain`
      },
      {
        heading: 'PROC — Processes',
        body: `Lists all running Windows processes.

"Active" tab — processes with a visible window (games, apps).
"Background" tab — system services, daemons.

Shortcuts:
• / — focus search
• Click — action menu (Memory Scan, PTR Chain)
• Double-click — go straight to Memory Scan

Auto-refresh updates the list every 3 seconds without reloading.`
      },
      {
        heading: 'FILE — Static Analysis',
        body: `Analyzes a PE file (.exe / .dll) without running it.

Shows:
• ImageBase — load base address
• EntryPoint — program entry point
• Sections — .text (code), .data (data), .rdata (constants), etc.
• AOB matches — addresses of found byte patterns

AOB pattern (Array of Bytes) — IDA-style byte sequence:
48 8B 05 ? ? ? ? 48 89

? is a wildcard — any byte. Used to skip addresses inside instructions that change with each compilation.

Found RVA is stable — works regardless of ASLR.
RIP Target — address referenced by the instruction (for MOV RAX, [RIP+offset]).`
      },
      {
        heading: 'MEM — Memory Scan',
        body: `Attaches to a live process and scans its memory.

Uses Windows API: OpenProcess → ReadProcessMemory → VirtualQueryEx.

Shows:
• Loaded modules (.exe + all .dll) with base addresses
• AOB pattern matches with absolute address and RVA

Note: absolute address (Address) changes on every game restart.
RVA = Address − ModuleBase — stable, use this one.

Requires a running process and memory read permissions.`
      },
      {
        heading: 'PTR — Pointer Chain',
        body: `Resolves a multi-level pointer chain to find dynamic objects.

Format: base_offset:offset1:offset2:offset3
Example: 0x1A2B00:0x10:0x20:0x5C

How it works:
1. module_base + 0x1A2B00 → read qword → get object address
2. object_address + 0x10 → read qword → next pointer
3. + 0x20 → read qword
4. + 0x5C → final address (struct field)

Used when an object is created dynamically (new/malloc) and its address changes. The pointer chain through a static root pointer stays constant.

History — last 5 resolved chains, click to reuse.`
      },
      {
        heading: 'Export .hpp',
        body: `After scanning, an "Export .hpp" button appears.

Generates a C++ header file with found offsets:

namespace Offsets {
    constexpr uintptr_t match_0 = 0x1A2B00; // .text
    constexpr uintptr_t match_1 = 0x1A3C10; // .text
}

Include the file in your project and use offsets directly.`
      },
      {
        heading: 'Static vs Dynamic',
        body: `Static offset (RVA from File/Memory Scan):
✓ Doesn't change between runs
✓ Survives game updates (if structure unchanged)
✓ Use as a constant in your tools

Dynamic address (Address from Memory Scan):
✗ Changes every run due to ASLR
✗ Can't be hardcoded
✓ Useful for right-now debugging

AOB pattern — most reliable method:
✓ Works even after game updates
✓ Doesn't depend on addresses — searches by byte signature
✓ RIP Target gives the final static offset automatically`
      }
    ]
  },
  pt: {
    title: 'Ajuda — OffsetDumper',
    sections: [
      { heading: 'O que é um offset?', body: `Um offset é o deslocamento do endereço base de um módulo até uma variável ou função na memória do processo.\n\nExemplo: game.exe carrega em 0x140000000. Variável "health" está em 0x1401A2B00. Offset = 0x1A2B00.\n\nDois tipos:\n• Estático — não muda entre execuções (RVA no arquivo PE)\n• Dinâmico — muda a cada execução por ASLR, precisa de cadeia de ponteiros` },
      { heading: 'PROC — Processos', body: `Lista todos os processos Windows em execução.\n\nAba "Ativos" — processos com janela visível.\nAba "Segundo plano" — serviços do sistema.\n\nAtalhos:\n• / — focar busca\n• Clique — menu de ações\n• Duplo clique — Memory Scan direto` },
      { heading: 'FILE — Análise Estática', body: `Analisa um arquivo PE (.exe / .dll) sem executá-lo.\n\nMostra seções, ImageBase, EntryPoint e correspondências AOB.\n\nPadrão AOB: 48 8B 05 ? ? ? ? 48 89\n? é curinga. O RVA encontrado é estável independente do ASLR.` },
      { heading: 'MEM — Varredura de Memória', body: `Conecta a um processo ativo e varre sua memória.\n\nMostra módulos carregados e correspondências AOB.\n\nAtenção: o endereço absoluto muda a cada reinício.\nUse o RVA = Endereço − BaseDoMódulo.` },
      { heading: 'PTR — Cadeia de Ponteiros', body: `Resolve uma cadeia de ponteiros para objetos dinâmicos.\n\nFormato: offset_base:offset1:offset2\nExemplo: 0x1A2B00:0x10:0x5C\n\nA cadeia através de um ponteiro raiz estático permanece constante.` },
      { heading: 'Exportar .hpp', body: `Após a varredura gera um arquivo C++ com os offsets encontrados no namespace Offsets {}.` },
      { heading: 'Estático vs Dinâmico', body: `RVA (estático) — não muda entre execuções, use como constante.\nEndereço absoluto (dinâmico) — muda por ASLR, apenas para depuração imediata.\nPadrão AOB — mais confiável, funciona mesmo após atualizações do jogo.` }
    ]
  },
  tr: {
    title: 'Yardım — OffsetDumper',
    sections: [
      { heading: 'Offset nedir?', body: `Offset, bir modülün temel adresinden bellekteki bir değişkene veya fonksiyona olan mesafedir.\n\nÖrnek: game.exe 0x140000000 adresine yüklenir. "health" değişkeni 0x1401A2B00 adresindedir. Offset = 0x1A2B00.\n\nİki tür offset:\n• Statik — çalıştırmalar arasında değişmez (PE dosyasındaki RVA)\n• Dinamik — ASLR nedeniyle her çalıştırmada değişir, işaretçi zinciri gerektirir` },
      { heading: 'PROC — İşlemler', body: `Tüm çalışan Windows işlemlerini listeler.\n\n"Aktif" sekmesi — görünür pencereli işlemler.\n"Arka plan" sekmesi — sistem servisleri.\n\nKısayollar:\n• / — aramaya odaklan\n• Tıklama — eylem menüsü\n• Çift tıklama — doğrudan Memory Scan` },
      { heading: 'FILE — Statik Analiz', body: `Çalıştırmadan bir PE dosyasını (.exe / .dll) analiz eder.\n\nBölümler, ImageBase, EntryPoint ve AOB eşleşmelerini gösterir.\n\nAOB deseni: 48 8B 05 ? ? ? ? 48 89\n? joker karakterdir. Bulunan RVA, ASLR'den bağımsız olarak stabildir.` },
      { heading: 'MEM — Bellek Taraması', body: `Canlı bir işleme bağlanır ve belleğini tarar.\n\nYüklenen modülleri ve AOB eşleşmelerini gösterir.\n\nDikkat: mutlak adres her yeniden başlatmada değişir.\nRVA = Adres − ModülTabanı kullanın.` },
      { heading: 'PTR — İşaretçi Zinciri', body: `Dinamik nesneler için çok seviyeli işaretçi zincirini çözer.\n\nFormat: temel_offset:offset1:offset2\nÖrnek: 0x1A2B00:0x10:0x5C\n\nStatik kök işaretçi üzerinden zincir sabit kalır.` },
      { heading: '.hpp Dışa Aktar', body: `Tarama sonrası Offsets {} namespace'i içinde bulunan offsetleri içeren bir C++ başlık dosyası oluşturur.` },
      { heading: 'Statik ve Dinamik', body: `RVA (statik) — çalıştırmalar arasında değişmez, sabit değer olarak kullanın.\nMutlak adres (dinamik) — ASLR nedeniyle değişir, yalnızca anlık hata ayıklama için.\nAOB deseni — en güvenilir, oyun güncellemelerinden sonra bile çalışır.` }
    ]
  }
}
