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

-- _G.create_entity = hook(rva(0x2099A0), "void* (__stdcall *)(char*, float, float, float, char*)",
--     function(func, name, x, y, z, kind)
--         local msg = string.format("%s (%s) (%f, %f, %f)", cstr(name), cstr(kind), x, y, z)
--         local result = func(name, 0, 0, 0, kind)
--         print(msg,result)
--         return result
--     end
-- )

-- _G.file_exists = hook(rva(0x12fb30), "uint32_t (__thiscall*)(void*, char*)", function(func, this, name)
--     local result = func(this,name)
--     print(cstr(name),result)
--     return result
-- end)


patch_python({name="^[Mm]enu"}, function(name, path, code)
    -- NOTE: Lua patterns treat ( ) as captures, so they must be escaped
    -- with %( ) when you meant a literal "def foo(arg):" string.
    local new_code, n = code:gsub(
        "def DrawBackMainMenu%(id%):",
        "def DrawBackMainMenu(id):\n\treturn\n"
    )
    print(string.format("[patch] %s (%s): %d replacement(s)", name, path, n))
    return new_code
end)