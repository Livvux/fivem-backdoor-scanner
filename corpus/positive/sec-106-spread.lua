-- Defanged: writes into every resource. Must trigger LAB-SEC-106.
for i = 0, GetNumResources() - 1 do
    local r = GetResourceByFindIndex(i)
    SaveResourceFile(r, 'fxmanifest.lua', '-- x', -1)
end
