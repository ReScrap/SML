-- _G.preload_library = hook(rva(0x192f90), "void* (__stdcall*) (char*, char*)", function(func,a,b)
--     -- local b = cstr(b):gsub(".pyc", ".py")
--     local res = func(a,b)
--     print("[PRELOAD]", cstr(a),cstr(b), res)
--     return res
-- end)

-- _G.pyparse = hook(rva(0x311f60), "void* (__cdecl*) (char*, void*, int, void*)", function(func, code, grammar, start, err_ret)
--     local res = func(code, grammar, start, err_ret)
--     print("[PY]", cstr(code))
--     return res
-- end)

_G.create_entity_hook = hook(rva(0x2099A0), "void* (__stdcall *)(char*, float, float, float, char*)",
    function(func, name, x, y, z, kind)
        local msg = string.format("%s (%s) (%f, %f, %f)", cstr(name), cstr(kind), x, y, z)
        local result = func(name, 0, 0, 0, kind)
        print(msg,result)
        return result
    end
)