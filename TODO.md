# TODO

- [x] Hook into .packed archive loading to patch files on-the-fly as they are read (for script injection/patching for example)
  - [x] Hook into Python module loading (`Scrap.PreloadLibrary` etc) to patch `.py` files and recompile them to `.pyc` on-the-fly
- [x] Lua api for python patching
- [ ] Python <-> Lua interop
- [ ] Steam P2P multiplayer
- [ ] Game asset patching (using scrap_parse+serde for Lua interop)
- [ ] Replace Lua with [Pluto](https://github.com/PlutoLang/Pluto) (there's an [open Issue](https://github.com/mlua-rs/mlua/issues/354) on mlua)
