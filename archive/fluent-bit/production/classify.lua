-- classify.lua: assign log_type to every container log record.
-- Priority: structured level field > embedded JSON/logfmt level > klog prefix >
--           Prometheus metric shape > error keywords > warn/debug > info.
local LEVEL_KEYS = {
  'level', 'lvl', 'Level', 'LEVEL', 'severity', 'severityText',
  'loglevel', 'log_level', 'logLevel'
}

local function bucket(lv)
  if type(lv) ~= 'string' then return nil end
  lv = lv:lower()
  if lv:find('error') or lv == 'err' or lv:find('fatal')
    or lv:find('panic') or lv:find('critical')
    or lv:find('emerg') or lv:find('alert') then
    return 'error'
  elseif lv:find('warn') then
    return 'warning'
  elseif lv:find('debug') or lv:find('trace') then
    return 'debug'
  elseif lv:find('info') or lv:find('notice') then
    return 'info'
  end
  return nil
end

local function level_from(rec)
  for _, k in ipairs(LEVEL_KEYS) do
    local b = bucket(rec[k])
    if b then return b end
  end
  return nil
end

-- Level embedded inside a raw JSON or logfmt line, e.g.
--   {"level":"error","msg":"..."}   level=warning   {'severity': 'debug'}
local function level_from_raw_text(t)
  local lv = t:match('"level"%s*:%s*"(.-)"')
          or t:match("'level'%s*:%s*'(.-)'")
          or t:match('"lvl"%s*:%s*"(.-)"')
          or t:match('"severity"%s*:%s*"(.-)"')
          or t:match('level=(%a+)')
  if lv then return bucket(lv) end
  return nil
end

local function build_text(rec)
  local parts = {}
  for _, k in ipairs({'message', 'msg', 'log', 'event', 'reason', 'description'}) do
    local v = rec[k]
    if type(v) == 'string' then table.insert(parts, v) end
  end
  return table.concat(parts, ' ')
end

local ERROR_WORDS = {
  'error', 'failed', 'failure', 'exception', 'traceback', 'panic',
  'fatal', 'critical', 'emerg', 'segmentation fault'
}

local function looks_like_error(t)
  local lower = t:lower()
  for _, w in ipairs(ERROR_WORDS) do
    if lower:find(w, 1, true) then return true end
  end
  return false
end

local function looks_like_warning(t)
  return t:lower():find('warn', 1, true) ~= nil
end

local function looks_like_debug(t)
  local lower = t:lower()
  return lower:find('debug', 1, true) ~= nil
     or lower:find('trace:', 1, true) ~= nil
end

-- Prometheus exposition format:
--   # HELP / # TYPE lines
--   metric_name 123
--   metric_name{label="v"} 123
local function looks_like_metric(t)
  if t:match('^#%s+HELP%s+') or t:match('^#%s+TYPE%s+') then return true end
  if t:match('^%s*[a-zA-Z_:][a-zA-Z0-9_:]*%s*%b{}%s*[-+%d%.eE]+%s*$') then return true end
  if t:match('^%s*[a-zA-Z_:][a-zA-Z0-9_:]*%s+[-+%d%.eE]+%s*$') then return true end
  return false
end

-- Minimal JSON string escaper (control chars -> \uXXXX)
local function json_escape(s)
  s = tostring(s or '')
  s = s:gsub('\\', '\\\\')
       :gsub('"', '\\"')
       :gsub('\n', '\\n')
       :gsub('\r', '\\r')
       :gsub('\t', '\\t')
       :gsub('%c', function(c) return string.format('\\u%04x', c:byte()) end)
  return s
end

-- Serialize a flat table (e.g. pod labels) to a JSON object string
local function table_to_json(tbl)
  if type(tbl) ~= 'table' then return '{}' end
  local keys = {}
  for k in pairs(tbl) do table.insert(keys, tostring(k)) end
  table.sort(keys)
  local items = {}
  for _, k in ipairs(keys) do
    local v = tbl[k]
    if type(v) == 'string' then
      table.insert(items, '"'..json_escape(k)..'":"'..json_escape(v)..'"')
    elseif type(v) == 'number' then
      table.insert(items, '"'..json_escape(k)..'":'..tostring(v))
    elseif type(v) == 'boolean' then
      table.insert(items, '"'..json_escape(k)..'":'..(v and 'true' or 'false'))
    end
  end
  return '{'..table.concat(items, ',')..'}'
end

function classify(tag, timestamp, record)
  local text = build_text(record)

  -- 1) explicit structured level wins
  local t = level_from(record)

  -- 2) level hidden inside a raw JSON / logfmt payload
  if not t then
    t = level_from_raw_text(text)
  end

  -- 3) klog prefixes used by kube-system components: E0825 / W0825 / I0825
  if not t and text:match('^%u%d%d%d%d%s') then
    local pfx = text:sub(1, 1)
    if pfx == 'E' then t = 'error'
    elseif pfx == 'W' then t = 'warning'
    else t = 'info' end
  end

  -- 4) content heuristics
  if not t and looks_like_metric(text) then t = 'metrics' end
  if not t and looks_like_error(text) then t = 'error' end
  if not t and looks_like_warning(text) then t = 'warning' end
  if not t and looks_like_debug(text) then t = 'debug' end

  if not t then t = 'info' end

  -- Pre-render a flat, greppable line for the file outputs:
  --   <date> - <namespace> - <pod>/<container> - <log message>
  local meta = record['kubernetes'] or {}
  local tsnum = tonumber(timestamp) or os.time()
  local ok_date, date_str = pcall(os.date, '!%Y-%m-%dT%H:%M:%SZ', math.floor(tsnum))
  if not ok_date or not date_str then date_str = os.date('!%Y-%m-%dT%H:%M:%SZ') end

  local ns   = tostring(meta['namespace_name'] or '-')
  local pod  = tostring(meta['pod_name'] or '-')
  local cont = tostring(meta['container_name'] or '-')
  -- collapse newlines/tabs so multi-line messages stay on one physical line
  local flat = tostring(text):gsub('[\r\n\t]+', ' ')

  local line = date_str..' - '..ns..' - '..pod..'/'..cont..' - '..flat

  record['log_type'] = t
  record['line'] = line

  return 2, timestamp, record
end


