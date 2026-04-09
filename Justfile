DLL := "d3d8"
test: install reset steam

install:
    cargo build -r --message-format short
    cp ./target/i686-pc-windows-msvc/release/sml_loader.dll E:/Games/Steam/steamapps/common/Scrapland/Bin/{{DLL}}.dll

install-dev:
    cargo build --message-format short
    cp ./target/i686-pc-windows-msvc/debug/sml_loader.dll E:/Games/Steam/steamapps/common/Scrapland/Bin/{{DLL}}.dll
    cp ./target/i686-pc-windows-msvc/debug/sml_loader.pdb E:/Games/Steam/steamapps/common/Scrapland/Bin/{{DLL}}.pdb

reset:
    -cp E:/Games/Steam/steamapps/common/Scrapland/Bin/Scrap.orig.exe E:/Games/Steam/steamapps/common/Scrapland/Bin/Scrap.exe

steam:
    start steam://run/897610

run:
    start E:/Games/Steam/steamapps/common/Scrapland/Bin/Scrap.exe

uninstall:
    rm E:/Games/Steam/steamapps/common/Scrapland/Bin/{{DLL}}.dll
