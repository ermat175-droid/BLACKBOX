# BLACKBOX

**Cyber Investigation & Attack Reconstruction Platform**

BLACKBOX — экспериментальная платформа для расследования киберинцидентов, анализа событий и реконструкции последовательности действий внутри изолированной лабораторной среды.

Проект направлен на изучение принципов Detection Engineering, Digital Forensics, Incident Response и Threat Hunting.

## Установка

> ⚠️ Это изолированная лаборатория с уязвимыми целями. Запускай только в доверенной сети.
> Нужны: **Docker** (запущенный демон) и ядро Linux с **BTF** (`/sys/kernel/btf/vmlinux`) для eBPF-сенсора Tetragon. Python ≥ 3.11.

Движок работает на Docker + Python и **не зависит от дистрибутива** — путь `install.sh` подходит для любого Linux (Arch, Debian, Ubuntu, Kali, Fedora…).

### Любой Linux — `install.sh`

```bash
git clone https://github.com/ermat175-droid/BLACKBOX
cd BLACKBOX
./install.sh          # venv + зависимости + команда `blackbox`
blackbox doctor       # проверка Docker / ядра / Python
blackbox up           # консоль:  http://127.0.0.1:8000/ui/
```

**Debian / Ubuntu / Kali** — `venv`, `pip` и Docker ставятся отдельно, поэтому один раз перед `install.sh`:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"    # затем перелогиниться
```

**Fedora / RHEL**:

```bash
sudo dnf install -y python3 docker
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"    # затем перелогиниться
```

На Arch `python` уже включает `venv`/`pip`, а Docker — пакет `docker`.

### Arch Linux — PKGBUILD (pacman-style)

```bash
# нативно через pacman, аккаунт AUR не нужен:
makepkg -si
blackbox up

# либо, когда пакет опубликован в AUR:
yay -S blackbox-git
```

### Команды

```text
blackbox up [--lan]   запустить консоль (--lan — открыть всем в твоём Wi-Fi)
blackbox down         остановить
blackbox status       состояние консоли / сенсора / целей
blackbox open         открыть в браузере
blackbox doctor       проверить предпосылки
blackbox clean        стереть локальные данные расследований и лаб-контейнеры
```

Данные расследований (`blackbox.db`, цели, прокси) хранятся локально и **не попадают в git** — каждый, кто склонирует репозиторий, стартует с чистой базой.


## Основные возможности

Планируемые возможности платформы:

- Генерация синтетических сценариев инцидентов.
- Сбор и нормализация событий.
- Обнаружение подозрительной активности с помощью правил обнаружения.
- Корреляция событий по PID, Parent PID, временным меткам и сетевым атрибутам.
- Сопоставление обнаруженных действий с MITRE ATT&CK.
- Построение временной шкалы инцидента.
- Реконструкция последовательности действий.
- Граф связей между событиями и процессами.
- AI Investigator для помощи в расследовании.
- Веб-интерфейс для анализа инцидентов.

## Архитектура

```text
BLACKBOX
│
├── Scenario Simulator
│   └── Генерация синтетических инцидентов
│
├── Event Collector
│   └── Получение событий
│
├── Event Normalization
│   └── Приведение событий к единому формату
│
├── Detection Engine
│   └── Обнаружение подозрительной активности
│
├── Correlation Engine
│   └── Связывание событий
│
├── MITRE ATT&CK Mapping
│   └── Классификация техник
│
├── Timeline Builder
│   └── Восстановление последовательности событий
│
├── Evidence Graph
│   └── Визуализация связей
│
├── AI Investigator
│   └── Помощь в анализе инцидентов
│
└── Web Dashboard
    └── Интерфейс расследования
```

## Текущий статус

### Реализовано

- [x] Базовая структура проекта.
- [x] Backend на Python и FastAPI.
- [x] SQLite для хранения событий.
- [x] SQLAlchemy ORM.
- [x] API для добавления и получения событий.
- [x] Синтетический сценарий BB-001.
- [x] Scenario Simulator для отправки тестовых событий в API.
- [x] Базовая Git-структура и `.gitignore`.
- [x] Event Normalization (канонический формат + raw + индексы).
- [x] Нормализация встроена в API ingestion (`POST /events`).
- [x] Collector: процессы и сеть через Tetragon (eBPF, без правки машин).
- [x] Collector: HTTP-запросы из логов Apache.
- [x] Correlation Engine: граф инцидента (`parent_of`, `spawned_by`,
      `connected_to`), у каждой связи есть обоснование.
- [x] Reconstruction Engine: история атаки по этапам (тактика + техника
      MITRE + обоснование + уверенность + ссылки на события),
      `GET /incidents/{case}/reconstruction`.
- [x] Detection + MITRE ATT&CK Mapping (детекторы в Reconstruction Engine).
- [x] Investigation Console (`GET /ui`): история атаки + граф + таймлайн +
      панель доказательств; языки RU/EN/KZ; сворачиваемые боковые колонки.
- [x] Timeline инцидента (`GET /incidents/{case}/timeline`).
- [x] Целостность доказательств: tamper-evident хеш-цепочка
      (`GET /integrity`), бейдж в UI.
- [x] Target Manager: загрузка сайтов-целей (образ / Dockerfile),
      запуск в песочнице на 127.0.0.1, авто-телеметрия; GUI
      `/ui/targets.html` (`/targets`, `/sensor`).
- [x] Инфраструктура защитника: авто-карта активов + blast-radius
      (`/incidents/{id}/infrastructure`, `/impact`); live-карта в UI.
- [x] Слепая валидация vs лог атакующего (`/validate`, `attacker_log.py`).
- [x] Генерация правил защиты (Sigma + Tetragon) из цепочки (`/rules`).
- [x] Живой блок атаки (Tetragon enforce, `POST/DELETE /enforce`) с жёстким
      фильтром безопасности (только артефакты атаки, не системные шеллы).
- [x] Подписанный самопроверяемый отчёт (`/report`, `verify_report.py`).
- [x] Офлайн-демо: фикстура инцидента + `scripts/replay.py`.
- [x] Лаборатория: уязвимые CTF-машины (Iceberg Zone 1), захват телеметрии
      проверен сквозным прогоном реальной атаки machine1.

### В разработке

- [ ] Презентация и запасная запись демо для финала ORTAQ.
- [ ] Compose как источник цели (многоконтейнерные сайты).
- [ ] AI Investigator (локальная LLM объясняет цепочки со ссылками).

## Технологии

| Компонент | Технология |
|---|---|
| Backend | Python, FastAPI |
| Database | SQLite, SQLAlchemy |
| Event format | JSON |
| Detection | Sigma-like rules |
| AI | Ollama, локальные LLM |
| Frontend | React, TypeScript |
| Visualization | Cytoscape.js |
| Environment | Linux, isolated lab |

## Безопасность

BLACKBOX разрабатывается как исследовательская лаборатория.

- Синтетические сценарии не выполняют реальные команды.
- Тестовые IP-адреса используются только как данные.
- Эксперименты с реальными системами проводятся только в собственных изолированных лабораториях.
- Локальные базы данных, секреты и конфигурации окружения не должны попадать в Git.

## Цель проекта

Создать платформу, которая сможет принимать события безопасности, выявлять подозрительные цепочки действий и реконструировать ход инцидента, предоставляя аналитику понятную картину произошедшего.

**BLACKBOX — from raw events to incident reconstruction.**
