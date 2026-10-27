-- Legitimate: posts a log line, never loads the response. Must stay clean.
PerformHttpRequest(Config.Webhook, function(code) print(code) end, 'POST', json.encode({ content = 'log' }))
