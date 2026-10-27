-- Legitimate: loads a file from its own resource. Must stay clean.
local chunk = load(LoadResourceFile(GetCurrentResourceName(), 'data.lua'))
local f = io.open(GetResourcePath(GetCurrentResourceName()) .. '/logs.txt', 'a')
