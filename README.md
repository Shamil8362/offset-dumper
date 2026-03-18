# OffsetDumper

![OffsetDumper](https://img.shields.io/badge/OffsetDumper-v1.3-0078d4?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Electron](https://img.shields.io/badge/Electron-28-47848F?style=for-the-badge)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge)
![CI](https://img.shields.io/github/actions/workflow/status/Shamil8362/offset-dumper/build.yml?style=for-the-badge&label=CI)

**Профессиональный инструмент для анализа памяти и дампинга оффсетов игр**

[Скачать](#установка) • [Функции](#функции) • [Использование](#использование) • [Сборка](#сборка)

---

> ### 💬 Хочешь стать разработчиком?
> Если ты сделал крутую модификацию или новую функцию — **напиши в Telegram: [@Andrey_Ch1katilo](https://t.me/Andrey_Ch1katilo)**

---

## О проекте

**OffsetDumper** — десктопное приложение для Windows с графическим интерфейсом, предназначенное для анализа памяти процессов, поиска оффсетов и автоматического дампинга структур данных из игр и приложений.

Построен на **Electron + React** (UI) и **C++ бэкенде**, который взаимодействует с Windows API через JSON IPC протокол.

> **⚠ Требует запуска от имени администратора** для чтения памяти процессов.
> Приложение показывает предупреждение если запущено без прав.

### Поддерживаемые движки

- ✅ **Source Engine x64** — CS:GO, CS2, TF2, L4D2, Portal 2
- ✅ **GoldSrc / Source x86** — Half-Life, CS 1.6, TFC
- ✅ **Unreal Engine 4/5** — Fortnite, PUBG и тысячи других UE4/UE5 игр
- ✅ **Unity IL2CPP** — большинство современных Unity игр
- ✅ **Любая игра** — через ручные AOB паттерны (вкладка SIGS)

---

## Функции

### ⊞ PROC — Менеджер процессов
- Разделение на **Активные** и **Фоновые** процессы
- **Авто-обновление** каждые 3 секунды
- Горячая клавиша `/` для поиска
- Двойной клик — мгновенный переход на Memory Scan

### ◈ FILE — Статический анализ PE файлов
- Анализ `.exe` и `.dll` **без запуска**
- Парсинг PE заголовков, AOB сканирование, RIP-relative вычисления

### ◎ MEM — Сканирование памяти
- Подключение через `ReadProcessMemory`
- Список модулей, AOB сканирование, экспорт в `.hpp`

### ⟡ PTR — Резолвер цепочек указателей
- **Визуальный редактор цепей** — добавляй/удаляй звенья кнопками
- **Именованная история** с сохранением между сессиями (до 20 записей)
- Формат: `base:offset1:offset2:offset3` (hex)

### ⚡ SIGS — Batch Scanner
- Именованные AOB сигнатуры совместимые с [hazedumper](https://github.com/frk1/hazedumper)
- **Live-валидация паттернов** — ошибки видны сразу при вводе
- Импорт/экспорт конфигов в JSON
- Экспорт в 5 форматах: `.hpp`, `.json`, `.cs`, `.py`, `.rs`

### ◬ NET — Автоматический думпер движков
- Source Engine x64/x86, Unreal Engine 4/5, Unity IL2CPP

---

## Форматы экспорта

| Формат | Пример |
|---|---|
| **C++ .hpp (flat)** | `constexpr uintptr_t m_iHealth = 0x100;` |
| **C++ .hpp (namespace)** | `namespace CCSPlayer { constexpr uintptr_t m_iHealth = 0x100; }` |
| **JSON** | `{ "CCSPlayer": { "m_iHealth": "0x100" } }` |
| **C# .cs** | `public const uint m_iHealth = 0x100;` |
| **Python .py** | `m_iHealth = 0x100` |
| **Rust .rs** | `pub const M_IHEALTH: usize = 0x100;` |

---

## Установка

### Быстрый старт (dev режим)

```bash
# Клонировать
git clone https://github.com/Shamil8362/offset-dumper.git
cd offset-dumper

# Установить зависимости
npm install

# Собрать C++ бэкенд (см. ниже)
# ...

# Запустить
npm run dev
```

### Готовый инсталлятор

Скачай последний релиз со страницы [Releases](../../releases) — там есть:
- `OffsetDumper-Setup-x.x.x.exe` — готовый установщик
- `offset_backend.exe.sha256` — хэш для проверки подлинности бэкенда

---

## Сборка

### Шаг 1 — Собрать C++ бэкенд

**Visual Studio 2022:**
```bat
cd backend
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
copy Release\offset_backend.exe ..\offset_backend.exe
```

**MinGW-w64:**
```bat
cd backend
x86_64-w64-mingw32-g++ -std=c++17 -O2 -DUNICODE -D_UNICODE ^
  -I src src/json_bridge.cpp src/utils.cpp src/pe_parser.cpp ^
  src/aob_scanner.cpp src/process.cpp src/pointer_scan.cpp ^
  src/offset_dump.cpp -o offset_backend.exe -lpsapi -static
```

### Шаг 2 — Запустить

```bash
npm run dev        # Dev режим с горячей перезагрузкой
npm run build      # Собрать .exe установщик (папка dist/)
```

> **CI/CD**: бэкенд собирается автоматически через GitHub Actions при каждом push в `main`.
> Бинарник **не хранится в репозитории** — только исходники.

---

## Архитектура

```
offset-dumper/
├── .github/workflows/
│   └── build.yml             ← CI: сборка бэкенда + Electron + авторелиз
├── backend/
│   └── src/
│       ├── json_bridge.cpp   ← IPC мост (stdin/stdout JSON)
│       ├── pe_parser.cpp     ← Парсинг PE заголовков
│       ├── aob_scanner.cpp   ← AOB паттерн поиск
│       ├── process.cpp       ← Windows API, ReadProcessMemory
│       ├── pointer_scan.cpp  ← Цепочки указателей
│       ├── offset_dump.cpp   ← Генерация .hpp файлов
│       └── utils.cpp         ← Утилиты
├── electron/
│   ├── main.js               ← Watchdog, admin-check, умные таймауты
│   └── preload.js            ← Context bridge + backend events
├── src/
│   ├── App.jsx               ← UI: все страницы и компоненты
│   ├── App.css               ← Стили (Win11 тёмная тема)
│   └── i18n.js               ← Переводы RU/EN/PT/TR
└── CHANGELOG.md
```

**IPC протокол:** Newline-delimited JSON через stdin/stdout.
Бэкенд логи и ошибки — отдельный stderr канал, не нарушает IPC.

---

## Языки интерфейса

🇷🇺 Русский  •  🇬🇧 English  •  🇧🇷 Português  •  🇹🇷 Türkçe

---

## Стек технологий

| Компонент | Технология |
|---|---|
| UI Framework | React 18 |
| Desktop Shell | Electron 28 |
| Build Tool | Vite 5 |
| Backend | C++17, Windows API |
| IPC | Newline-delimited JSON |
| Styling | CSS Variables, Win11 тёмная тема |
| CI/CD | GitHub Actions |

---

## Контрибьюторы

| Разработчик | Роль |
|---|---|
| [@Shamil8362](https://github.com/Shamil8362) | Основной разработчик |

> ### Хочешь попасть в эту таблицу?
> Сделай крутое обновление и напиши в Telegram: **[@Andrey_Ch1katilo](https://t.me/Andrey_Ch1katilo)**

---

## Лицензия

[MIT License](LICENSE) — используй свободно для личных и образовательных целей.

---

Сделано с ❤️ by [Shamil8362](https://github.com/Shamil8362)

⭐ Если проект полезен — поставь звезду!
