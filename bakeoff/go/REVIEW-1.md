<review round="1">
  <summary>Приёмка зелёная, но ревью нашло ошибки, которые проявятся под нагрузкой. Исправь их, не ломая приёмку.</summary>

  <finding id="R1" severity="high" file="main.go" func="tryUpstream">
    На каждый запрос создаётся новый http.Client с http.Transport{DisableKeepAlives: true}. Пула соединений нет: под нагрузкой это TCP-handshake на каждый запрос и исчерпание портов.
    Требование: один общий http.Client на процесс (глобальная переменная, создаётся в main), Transport с MaxIdleConns >= 1024, MaxIdleConnsPerHost >= 512, IdleConnTimeout 90s, DisableCompression: true, DialContext с таймаутом подключения 2s. Keep-alive включён.
    Важно: тест client_cancel и ttft_timeout_failover требуют, чтобы при отмене соединение с upstream ЗАКРЫВАЛОСЬ. С пулом это обеспечивается отменой контекста запроса: для каждой попытки создавай дочерний context.WithCancel от r.Context() и вызывай cancel() при выходе из попытки (в том числе при TTFT-таймауте). Незавершённое тело при отменённом контексте не возвращается в пул, соединение закрывается.
  </finding>

  <finding id="R2" severity="high" file="main.go" func="streamRest">
    Гонка данных: goroutine пишет в http.ResponseWriter, а обработчик может вернуться по ctx.Done() раньше неё. После выхода из обработчика ResponseWriter использовать нельзя — возможна паника.
    Требование: убрать goroutine из streamRest. Читать upstream и писать клиенту в одном цикле в goroutine обработчика. Отмена обеспечивается контекстом: при отключении клиента r.Context() отменяется, чтение resp.Body возвращает ошибку, цикл завершается.
    То же для ожидания первого чанка: goroutine, читающая первый чанк, не должна пережить функцию и не должна писать в ResponseWriter; после TTFT-таймаута отмени контекст попытки и дождись завершения goroutine чтения (канал), прежде чем вернуться.
  </finding>

  <finding id="R3" severity="medium" file="main.go" func="handleChat, isStream">
    Тело читается без ограничения размера, ошибка io.ReadAll игнорируется.
    Требование: http.MaxBytesReader с лимитом 10 MB; при ошибке чтения — 400 с JSON-ошибкой, при превышении — 413.
  </finding>

  <acceptance>
    go build -o proxy.exe . && go vet ./... && python check.py --cmd "./proxy.exe" --base-port 18100
    Ожидается: ИТОГ: 10/10 и чистый go vet. (Детектор гонок на этой машине недоступен: нет cgo. Не пытайся собирать с -race.)
  </acceptance>

  <rules>
    Сначала напиши план на 5–10 строк: что меняешь и какие тесты приёмки это может сломать. Меняй только main.go. check.py не трогай. В конце допиши в REPORT.md раздел «Раунд ревью 1»: что исправлено и результат проверки.
  </rules>
</review>
