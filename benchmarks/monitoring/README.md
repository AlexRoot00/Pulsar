# Мониторинг стенда

node_exporter на обоих серверах, ebpf_exporter на DUT, vmagent шлёт всё
remote_write в существующий VictoriaMetrics. Только systemd, без докера —
на DUT в измеряемом пути не должно быть лишнего.

## Установка

На каждом сервере, от root, из корня репозитория:

```bash
# DUT (тот, на котором висит XDP)
ROLE=dut STAND=pulsar-bench \
  VM_URL=https://vm.example.net/api/v1/write \
  VM_USER=... VM_PASS=... \
  EXPORTER_CPUS=0,1 \
  bash benchmarks/monitoring/setup_monitoring.sh

# генератор
ROLE=gen STAND=pulsar-bench \
  VM_URL=https://vm.example.net/api/v1/write \
  VM_USER=... VM_PASS=... \
  bash benchmarks/monitoring/setup_monitoring.sh
```

Метрики приезжают с метками `stand`, `role` (`dut`/`gen`) и `host` — два
прогона на разных стендах не перепутаются.

Снести перед возвратом арендованных машин:

```bash
ACTION=uninstall bash benchmarks/monitoring/setup_monitoring.sh
```

Порты: node_exporter `:9100`, ebpf_exporter `:9435`, vmagent UI `:8429`.
Наружу их открывать не надо — vmagent скрейпит localhost и пушит сам.

## Важно: ebpf_exporter влияет на измерение

ebpf_exporter грузит **свои** BPF-программы (kprobe/tracepoint) и держит свои
map'ы. На DUT это прямая добавка к тому, что ты меряешь. Поэтому:

- Эталонные цифры throughput снимай с **остановленным** ebpf_exporter:
  `systemctl stop ebpf_exporter`.
- Диагностические проходы (где смотришь softirq/runqueue) — с включённым, и
  в отчёте это отмечай отдельной серией.
- Совсем не ставить: `EBPF_EXPORTER=0`.

Требования: ядро с BTF (`CONFIG_DEBUG_INFO_BTF=y`), иначе часть примеров не
загрузится. Проверить: `ls /sys/kernel/btf/vmlinux`.

`EXPORTER_CPUS` прописывает `CPUAffinity=` в юниты — прижми экспортеры к
ядрам, которые **не** обрабатывают RX-очереди тестируемого интерфейса.
Ядра RX смотри в `/proc/interrupts` по имени интерфейса.

## Что смотреть после прогона

С node_exporter:

- `node_network_receive_packets_total{device="enp..."}` — RX на уровне
  драйвера. Сверять с `rx_packets` из `ebpf-ctl`: XDP-дропы в этот счётчик
  попадают не на всех драйверах, поэтому расхождение само по себе не баг.
- `node_network_receive_drop_total`, `node_softnet_dropped_total`,
  `node_softnet_times_squeezed_total` — упёрлись ли в netdev budget.
- `node_cpu_seconds_total{mode="softirq"}` по ядрам — реальная стоимость
  обработки, честнее чем `Average:` из mpstat по всем ядрам.
- На генераторе: `node_network_transmit_packets_total` — независимая проверка,
  что pktgen выдал ожидаемый PPS. Если не выдал, ты померил генератор.

С ebpf_exporter (имена зависят от набора примеров в релизе):
`softirqs` — время в NET_RX; `runqlat` — задержка планировщика, видно когда
демон и экспортеры начинают конкурировать с softirq за ядра.

## Результаты прогона в тот же TSDB

node_exporter поднят с `--collector.textfile.directory=/var/lib/node_exporter/textfile`.
Кидай туда `.prom`-файл после прогона, и результат ляжет рядом с системными
метриками, с теми же метками стенда:

```bash
cat > /var/lib/node_exporter/textfile/bench.prom.$$ <<'EOF'
# HELP bench_xdp_pps Packets per second measured on the DUT
# TYPE bench_xdp_pps gauge
bench_xdp_pps{scenario="s2",backend="xdp"} 3421000
# HELP bench_xdp_drop_pps ACL drops per second
# TYPE bench_xdp_drop_pps gauge
bench_xdp_drop_pps{scenario="s2",backend="xdp"} 3420800
EOF
mv /var/lib/node_exporter/textfile/bench.prom.$$ /var/lib/node_exporter/textfile/bench.prom
```

Запись через временный файл + `mv` обязательна: node_exporter читает каталог
по каждому скрейпу и подхватит недописанный файл.

## Оговорки по скрипту

- Версии резолвятся по GitHub API (`latest`), при недоступности берётся
  пин из `*_FALLBACK`. Имена ассетов у релизов иногда меняются — если
  скачивание упало, скрипт печатает URL и падает, версия задаётся явно через
  `NODE_EXPORTER_VERSION` / `EBPF_EXPORTER_VERSION` / `VMUTILS_VERSION`.
- Бинарник внутри архива ищется через `find`, а не по захардкоженному пути,
  чтобы смена раскладки архива не ломала установку молча.
- Из `EBPF_EXPORTER_CONFIGS` включаются только те конфиги, которые реально
  есть в релизе; отсутствующие печатаются в WARN вместе со списком доступных.
