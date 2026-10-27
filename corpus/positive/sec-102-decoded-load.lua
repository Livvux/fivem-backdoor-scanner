-- Defanged: runs text that only exists after decoding. Must trigger LAB-SEC-102.
load(string.char(112, 114, 105, 110, 116, 40, 39, 104, 105, 39, 41))()
