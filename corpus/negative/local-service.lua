-- Legitimate: local service and a named host. Must stay clean.
PerformHttpRequest('http://127.0.0.1:3000/hook', function() end)
local locale = GetConvar('ox:locale', 'en')
