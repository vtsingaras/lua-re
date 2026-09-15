local module = require("example")
local captured = 17
local function calculate(a, b, ...)
  local text = "binary\\000\\255"
  local t = {name = text, 10, 20, false}
  for i = 1, a do
    captured = captured + i
    t[i] = (i * b) % 7
  end
  for k, v in pairs(t) do
    if k == "name" then t.name = tostring(v) end
  end
  repeat a = a - 1 until a < 2
  while b > 0 do b = b - 1 end
  local yes = a == b
  local no = not yes
  local function nested(x)
    captured = captured + x
    return captured
  end
  return nested, t, yes and no or #text, ...
end
function exported(a, b)
  local fn = calculate(a, b)
  return fn(3)
end
return calculate, exported
